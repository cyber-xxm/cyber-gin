package bootstrap

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"github.com/gin-gonic/gin"
	"io"
	"net"
	"net/http"
	"os"
	"path"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

var (
	bufReaderPool   sync.Pool
	bufWriter2kPool sync.Pool
	bufWriter4kPool sync.Pool
)

func bufWriterPool(size int) *sync.Pool {
	switch size {
	case 2 << 10:
		return &bufWriter2kPool
	case 4 << 10:
		return &bufWriter4kPool
	}
	return nil
}

func newBufReader(r io.Reader) *bufio.Reader {
	if v := bufReaderPool.Get(); v != nil {
		br := v.(*bufio.Reader)
		br.Reset(r)
		return br
	}
	// Note: if this reader size is ever changed, update
	// TestHandlerBodyClose's assumptions.
	return bufio.NewReader(r)
}

func putBufReader(br *bufio.Reader) {
	br.Reset(nil)
	bufReaderPool.Put(br)
}

func newBufWriterSize(w io.Writer, size int) *bufio.Writer {
	pool := bufWriterPool(size)
	if pool != nil {
		if v := pool.Get(); v != nil {
			bw := v.(*bufio.Writer)
			bw.Reset(w)
			return bw
		}
	}
	return bufio.NewWriterSize(w, size)
}

func putBufWriter(bw *bufio.Writer) {
	bw.Reset(nil)
	if pool := bufWriterPool(bw.Available()); pool != nil {
		pool.Put(bw)
	}
}

type conn struct {
	rwc net.Conn

	r *connReader

	// cancelCtx cancels the connection-level context.
	cancelCtx context.CancelFunc

	Handler http.Handler // handler to invoke, http.DefaultServeMux if nil

	remoteAddr string

	// bufReader reads from r.
	bufReader *bufio.Reader

	// bufWriter writes to checkConnErrorWriter{c}, which populates werr on error.
	bufWriter *bufio.Writer

	// lastMethod is the method of the most recent request
	// on this connection, if any.
	lastMethod string

	ConnState func(net.Conn, http.ConnState)

	curState atomic.Uint64 // packed (unixtime<<8|uint8(ConnState))

	curReq atomic.Pointer[response] // (which has a Request in it)

	activeConn map[*conn]struct{}

	mu sync.Mutex

	werr error
}

func (c *conn) setState(nc net.Conn, state http.ConnState, runHook bool) {
	switch state {
	case http.StateNew:
		c.trackConn(true)
	case http.StateHijacked, http.StateClosed:
		c.trackConn(false)
	default:
		// panic("unhandled default case")
	}
	if state > 0xff || state < 0 {
		panic("internal error")
	}
	packedState := uint64(time.Now().Unix()<<8) | uint64(state)
	c.curState.Store(packedState)
	if !runHook {
		return
	}
	if hook := c.ConnState; hook != nil {
		hook(nc, state)
	}
}

func (c *conn) handleTCPConnection(ctx context.Context) {
	if ra := c.rwc.RemoteAddr(); ra != nil {
		fmt.Println(fmt.Sprintf("new TCP connection from %s", c.rwc.RemoteAddr()))
		c.remoteAddr = ra.String()
	}

	defer func() {
		if err := recover(); err != nil && err != http.ErrAbortHandler {
			const size = 64 << 10
			buf := make([]byte, size)
			buf = buf[:runtime.Stack(buf, false)]
			fmt.Println(fmt.Sprintf("http: panic serving %v: %v\n%s", c.remoteAddr, err, buf))
		}
		c.close()
		c.setState(c.rwc, http.StateClosed, true)
	}()

	ctx, cancelCtx := context.WithCancel(ctx)
	c.cancelCtx = cancelCtx
	defer cancelCtx()

	c.r = &connReader{conn: c}
	c.bufReader = newBufReader(c.rwc)
	c.bufWriter = newBufWriterSize(checkConnErrorWriter{c}, 4<<10)

	for {
		// 解析HTTP请求
		w, err := c.readRequest(ctx)
		c.setState(c.rwc, http.StateActive, true)
		if err != nil {
			const errorHeaders = "\r\nContent-Type: text/plain; charset=utf-8\r\nConnection: close\r\n\r\n"

			switch {
			case errors.Is(err, errors.New("http: request too large")):
				// Their HTTP client may or may not be
				// able to read this if we're
				// responding to them and hanging up
				// while they're still writing their
				// request. Undefined behavior.
				const publicErr = "431 Request Header Fields Too Large"
				fmt.Fprintf(c.rwc, "HTTP/1.1 "+publicErr+errorHeaders+publicErr)
				c.closeWriteAndWait()
				return

			case isUnsupportedTEError(err):
				// Respond as per RFC 7230 Section 3.3.1 which says,
				//      A server that receives a request message with a
				//      transfer coding it does not understand SHOULD
				//      respond with 501 (Unimplemented).
				code := http.StatusNotImplemented

				// We purposefully aren't echoing back the transfer-encoding's value,
				// so as to mitigate the risk of cross side scripting by an attacker.
				fmt.Fprintf(c.rwc, "HTTP/1.1 %d %s%sUnsupported transfer encoding", code, http.StatusText(code), errorHeaders)
				return

			case isCommonNetReadError(err):
				return // don't reply

			default:
				var v statusError
				if errors.As(err, &v) {
					fmt.Fprintf(c.rwc, "HTTP/1.1 %d %s: %s%s%d %s: %s", v.code, http.StatusText(v.code), v.text, errorHeaders, v.code, http.StatusText(v.code), v.text)
					return
				}
				const publicErr = "400 Bad Request"
				fmt.Fprintf(c.rwc, "HTTP/1.1 "+publicErr+errorHeaders+publicErr)
				return
			}
		}

		req := w.req

		c.curReq.Store(w)
		w.conn.r.startBackgroundRead()
		// 处理请求
		// TCP 响应已通过 ginEngine 处理，响应已通过 conn 写回
		c.Handler.ServeHTTP(w, req)
		w.cancelCtx()
		w.finishRequest()
		c.rwc.SetWriteDeadline(time.Time{})
		c.setState(c.rwc, http.StateIdle, true)
		c.curReq.Store(nil)

		c.rwc.SetReadDeadline(time.Time{})

		// Wait for the connection to become readable again before trying to
		// read the next request. This prevents a ReadHeaderTimeout or
		// ReadTimeout from starting until the first bytes of the next request
		// have been received.
		if _, err := c.bufReader.Peek(4); err != nil {
			fmt.Println("bufReader peek err: ", err.Error())
			// 关键修改：使用Peek检测连接是否关闭
			if err == io.EOF {
				fmt.Println("Client closed connection")
				return
			}
		}

		c.rwc.SetReadDeadline(time.Time{})
	}
}

func (c *conn) readRequest(ctx context.Context) (*response, error) {
	// 设置读写超时（30秒）
	//c.rwc.SetReadDeadline(time.Now().Add(60 * time.Second))
	//c.rwc.SetWriteDeadline(time.Now().Add(60 * time.Second))
	c.rwc.SetReadDeadline(time.Time{})

	if c.lastMethod == "POST" {
		// RFC 7230 section 3 tolerance for old buggy clients.
		peek, _ := c.bufReader.Peek(4) // ReadRequest will get err below
		c.bufReader.Discard(numLeadingCRorLF(peek))
	}

	req, err := http.ReadRequest(c.bufReader)
	if err != nil {
		return nil, err
	}

	c.lastMethod = req.Method
	ctx, cancelCtx := context.WithCancel(ctx)
	req.RemoteAddr = c.remoteAddr
	// 创建新的ResponseWriter实例（每次请求独立）
	w := &response{
		conn:          c,
		cancelCtx:     cancelCtx,
		req:           req,
		reqBody:       req.Body,
		handlerHeader: make(http.Header),
		contentLength: -1,
		closeNotifyCh: make(chan bool, 1),
	}
	w.cw.res = w
	w.w = newBufWriterSize(&w.cw, 2048)
	return w, nil
}

func (c *conn) trackConn(add bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.activeConn == nil {
		c.activeConn = make(map[*conn]struct{})
	}
	if add {
		c.activeConn[c] = struct{}{}
	} else {
		delete(c.activeConn, c)
	}
}

// Close the connection.
func (c *conn) close() {
	c.finalFlush()
	c.rwc.Close()
}

func (c *conn) closeWriteAndWait() {
	c.finalFlush()
	if tcp, ok := c.rwc.(closeWriter); ok {
		tcp.CloseWrite()
	}

	// When we return from closeWriteAndWait, the caller will fully close the
	// connection. If client is still writing to the connection, this will cause
	// the write to fail with ECONNRESET or similar. Unfortunately, many TCP
	// implementations will also drop unread packets from the client's read buffer
	// when a write fails, causing our final response to be truncated away too.
	//
	// As a result, https://www.rfc-editor.org/rfc/rfc7230#section-6.6 recommends
	// that “[t]he server … continues to read from the connection until it
	// receives a corresponding close by the client, or until the server is
	// reasonably certain that its own TCP stack has received the client's
	// acknowledgement of the packet(s) containing the server's last response.”
	//
	// Unfortunately, we have no straightforward way to be “reasonably certain”
	// that we have received the client's ACK, and at any rate we don't want to
	// allow a misbehaving client to soak up server connections indefinitely by
	// withholding an ACK, nor do we want to go through the complexity or overhead
	// of using low-level APIs to figure out when a TCP round-trip has completed.
	//
	// Instead, we declare that we are “reasonably certain” that we received the
	// ACK if maxRSTAvoidanceDelay has elapsed.
	time.Sleep(500 * time.Millisecond)
}

func (c *conn) finalFlush() {
	if c.bufReader != nil {
		// Steal the bufio.Reader (~4KB worth of memory) and its associated
		// reader for a future connection.
		putBufReader(c.bufReader)
		c.bufReader = nil
	}

	if c.bufWriter != nil {
		c.bufWriter.Flush()
		// Steal the bufio.Writer (~4KB worth of memory) and its associated
		// writer for a future connection.
		putBufWriter(c.bufWriter)
		c.bufWriter = nil
	}
}

type connReader struct {
	conn    *conn
	mu      sync.Mutex // guards following
	hasByte bool
	byteBuf [1]byte
	cond    *sync.Cond
	inRead  bool
	aborted bool  // set true before conn.rwc deadline is set to past
	remain  int64 // bytes remaining
}

func (cr *connReader) lock() {
	cr.mu.Lock()
	if cr.cond == nil {
		cr.cond = sync.NewCond(&cr.mu)
	}
}

func (cr *connReader) unlock() { cr.mu.Unlock() }

func (cr *connReader) startBackgroundRead() {
	cr.lock()
	defer cr.unlock()
	if cr.inRead {
		panic("invalid concurrent Body.Read call")
	}
	if cr.hasByte {
		return
	}
	cr.inRead = true
	cr.conn.rwc.SetReadDeadline(time.Time{})
	go cr.backgroundRead()
}

func (cr *connReader) backgroundRead() {
	n, err := cr.conn.rwc.Read(cr.byteBuf[:])
	cr.lock()
	if n == 1 {
		cr.hasByte = true
		// We were past the end of the previous request's body already
		// (since we wouldn't be in a background read otherwise), so
		// this is a pipelined HTTP request. Prior to Go 1.11 we used to
		// send on the CloseNotify channel and cancel the context here,
		// but the behavior was documented as only "may", and we only
		// did that because that's how CloseNotify accidentally behaved
		// in very early Go releases prior to context support. Once we
		// added context support, people used a Handler's
		// Request.Context() and passed it along. Having that context
		// cancel on pipelined HTTP requests caused problems.
		// Fortunately, almost nothing uses HTTP/1.x pipelining.
		// Unfortunately, apt-get does, or sometimes does.
		// New Go 1.11 behavior: don't fire CloseNotify or cancel
		// contexts on pipelined requests. Shouldn't affect people, but
		// fixes cases like Issue 23921. This does mean that a client
		// closing their TCP connection after sending a pipelined
		// request won't cancel the context, but we'll catch that on any
		// write failure (in checkConnErrorWriter.Write).
		// If the server never writes, yes, there are still contrived
		// server & client behaviors where this fails to ever cancel the
		// context, but that's kinda why HTTP/1.x pipelining died
		// anyway.
	}
	var ne net.Error
	if errors.As(err, &ne) && cr.aborted && ne.Timeout() {
		// Ignore this error. It's the expected error from
		// another goroutine calling abortPendingRead.
	}
	cr.aborted = false
	cr.inRead = false
	cr.unlock()
	cr.cond.Broadcast()
}

func (cr *connReader) abortPendingRead() {
	cr.lock()
	defer cr.unlock()
	if !cr.inRead {
		return
	}
	cr.aborted = true
	cr.conn.rwc.SetReadDeadline(time.Unix(1, 0))
	for cr.inRead {
		cr.cond.Wait()
	}
	cr.conn.rwc.SetReadDeadline(time.Time{})
}

func (cr *connReader) setReadLimit(remain int64) { cr.remain = remain }
func (cr *connReader) setInfiniteReadLimit()     { cr.remain = 1<<63 - 1 }
func (cr *connReader) hitReadLimit() bool        { return cr.remain <= 0 }

// handleReadError is called whenever a Read from the client returns a
// non-nil error.
//
// The provided non-nil err is almost always io.EOF or a "use of
// closed network connection". In any case, the error is not
// particularly interesting, except perhaps for debugging during
// development. Any error means the connection is dead and we should
// down its context.
//
// It may be called from multiple goroutines.
func (cr *connReader) handleReadError(_ error) {
	cr.conn.cancelCtx()
	cr.closeNotify()
}

// may be called from multiple goroutines.
func (cr *connReader) closeNotify() {
	res := cr.conn.curReq.Load()
	if res != nil && !res.didCloseNotify.Swap(true) {
		res.closeNotifyCh <- true
	}
}

func (cr *connReader) Read(p []byte) (n int, err error) {
	cr.lock()
	if cr.inRead {
		cr.unlock()
		panic("invalid concurrent Body.Read call")
	}
	if cr.hitReadLimit() {
		cr.unlock()
		return 0, io.EOF
	}
	if len(p) == 0 {
		cr.unlock()
		return 0, nil
	}
	if int64(len(p)) > cr.remain {
		p = p[:cr.remain]
	}
	if cr.hasByte {
		p[0] = cr.byteBuf[0]
		cr.hasByte = false
		cr.unlock()
		return 1, nil
	}
	cr.inRead = true
	cr.unlock()
	n, err = cr.conn.rwc.Read(p)

	cr.lock()
	cr.inRead = false
	if err != nil {
		cr.handleReadError(err)
	}
	cr.remain -= int64(n)
	cr.unlock()

	cr.cond.Broadcast()
	return n, err
}

type extraHeader struct {
	contentType      string
	connection       string
	transferEncoding string
	date             []byte // written if not nil
	contentLength    []byte // written if not nil
}

// Sorted the same as extraHeader.Write's loop.
var extraHeaderKeys = [][]byte{
	[]byte("Content-Type"),
	[]byte("Connection"),
	[]byte("Transfer-Encoding"),
}

var (
	headerContentLength = []byte("Content-Length: ")
	headerDate          = []byte("Date: ")
)

// Write writes the handlerHeader described in h to w.
//
// This method has a value receiver, despite the somewhat large size
// of h, because it prevents an allocation. The escape analysis isn't
// smart enough to realize this function doesn't mutate h.
func (h extraHeader) Write(w *bufio.Writer) {
	if h.date != nil {
		w.Write(headerDate)
		w.Write(h.date)
		w.Write(crlf)
	}
	if h.contentLength != nil {
		w.Write(headerContentLength)
		w.Write(h.contentLength)
		w.Write(crlf)
	}
	for i, v := range []string{h.contentType, h.connection, h.transferEncoding} {
		if v != "" {
			w.Write(extraHeaderKeys[i])
			w.Write(colonSpace)
			w.WriteString(v)
			w.Write(crlf)
		}
	}
}

type chunkWriter struct {
	res *response

	// header is either nil or a deep clone of res.handlerHeader
	// at the time of res.writeHeader, if res.writeHeader is
	// called and extra buffering is being done to calculate
	// Content-Type and/or Content-Length.
	header http.Header

	// wroteHeader tells whether the header's been written to "the
	// wire" (or rather: w.conn.buf). this is unlike
	// (*response).wroteHeader, which tells only whether it was
	// logically written.
	wroteHeader bool

	// set by the writeHeader method:
	chunking bool // using chunked transfer encoding for reply body
}

var (
	crlf       = []byte("\r\n")
	colonSpace = []byte(": ")
)

func (cw *chunkWriter) Write(p []byte) (n int, err error) {
	fmt.Println("chunkWriter write")
	if !cw.wroteHeader {
		cw.writeHeader(p)
	}
	if cw.res.req.Method == "HEAD" {
		// Eat writes.
		return len(p), nil
	}
	if cw.chunking {
		_, err = fmt.Fprintf(cw.res.conn.bufWriter, "%x\r\n", len(p))
		if err != nil {
			cw.res.conn.rwc.Close()
			return
		}
	}
	n, err = cw.res.conn.bufWriter.Write(p)
	if cw.chunking && err == nil {
		_, err = cw.res.conn.bufWriter.Write(crlf)
	}
	if err != nil {
		cw.res.conn.rwc.Close()
	}
	return
}

func (cw *chunkWriter) flush() error {
	fmt.Println("chunkWriter flush")
	if !cw.wroteHeader {
		cw.writeHeader(nil)
	}
	return cw.res.conn.bufWriter.Flush()
}

func (cw *chunkWriter) close() {
	fmt.Println("chunkWriter close")
	if !cw.wroteHeader {
		cw.writeHeader(nil)
	}
	if cw.chunking {
		bw := cw.res.conn.bufWriter // conn's bufio writer
		// zero chunk to mark EOF
		bw.WriteString("0\r\n")
		if trailers := cw.res.finalTrailers(); trailers != nil {
			trailers.Write(bw) // the writer handles noting errors
		}
		// final blank line after the trailers (whether
		// present or not)
		bw.WriteString("\r\n")
	}
}

func (cw *chunkWriter) writeHeader(p []byte) {
	fmt.Println("chunkWriter writeHeader")
	header := cw.header
	var excludeHeader map[string]bool
	var setHeader extraHeader
	if p != nil {
		setHeader.contentLength = strconv.AppendInt(cw.res.clenBuf[:0], int64(len(p)), 10)
	}
	if "" != header.Get("Date") {
		setHeader.date = appendTime(cw.res.dateBuf[:0], time.Now())
	}
	w := cw.res
	writeStatusLine(w.conn.bufWriter, w.req.ProtoAtLeast(1, 1), w.status, w.statusBuf[:])
	cw.header.WriteSubset(w.conn.bufWriter, excludeHeader)
	setHeader.Write(w.conn.bufWriter)
	w.conn.bufWriter.Write(crlf)
}

func appendTime(b []byte, t time.Time) []byte {
	const days = "SunMonTueWedThuFriSat"
	const months = "JanFebMarAprMayJunJulAugSepOctNovDec"

	t = t.UTC()
	yy, mm, dd := t.Date()
	hh, mn, ss := t.Clock()
	day := days[3*t.Weekday():]
	mon := months[3*(mm-1):]

	return append(b,
		day[0], day[1], day[2], ',', ' ',
		byte('0'+dd/10), byte('0'+dd%10), ' ',
		mon[0], mon[1], mon[2], ' ',
		byte('0'+yy/1000), byte('0'+(yy/100)%10), byte('0'+(yy/10)%10), byte('0'+yy%10), ' ',
		byte('0'+hh/10), byte('0'+hh%10), ':',
		byte('0'+mn/10), byte('0'+mn%10), ':',
		byte('0'+ss/10), byte('0'+ss%10), ' ',
		'G', 'M', 'T')
}

// 自定义实现一个 tcp 连接的 http.ResponseWriter 和 http.Request
type response struct {
	conn          *conn
	cw            chunkWriter
	w             *bufio.Writer // buffers output in chunks to chunkWriter
	reqBody       io.ReadCloser
	handlerHeader http.Header
	req           *http.Request // 记录当前请求的上下文
	// cancelCtx cancels the connection-level context.
	cancelCtx        context.CancelFunc
	handlerDone      atomic.Bool // set true when the handler exits
	trailers         []string
	written          int64 // number of bytes written in body
	wroteHeader      bool  // a non-1xx header has been (logically) written
	closeAfterReply  bool
	status           int   // status code passed to WriteHeader
	contentLength    int64 // explicitly-declared Content-Length; or -1
	writeContinueMu  sync.Mutex
	dateBuf          [len("Mon, 02 Jan 2006 15:04:05 GMT")]byte
	canWriteContinue atomic.Bool
	closeNotifyCh    chan bool
	statusBuf        [3]byte
	clenBuf          [10]byte
	calledHeader     bool        // handler accessed handlerHeader via Header
	didCloseNotify   atomic.Bool // atomic (only false->true winner should send)
}

func (w *response) Flush() {
	fmt.Println("response flush")
	w.FlushError()
}

func (w *response) FlushError() error {
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}
	err := w.w.Flush()
	e2 := w.cw.flush()
	if err == nil {
		err = e2
	}
	return err
}

func (w *response) SetReadDeadline(deadline time.Time) error {
	fmt.Println("response setReadDeadline")
	return w.conn.rwc.SetReadDeadline(deadline)
}

func (w *response) SetWriteDeadline(deadline time.Time) error {
	fmt.Println("response setWriteDeadline")
	return w.conn.rwc.SetWriteDeadline(deadline)
}

func (w *response) CloseNotify() <-chan bool {
	fmt.Println("response closeNotify")
	if w.handlerDone.Load() {
		panic("net/http: CloseNotify called after ServeHTTP finished")
	}
	return w.closeNotifyCh
}

func (w *response) sendExpectationFailed() {
	// TODO(bradfitz): let ServeHTTP handlers handle
	// requests with non-standard expectation[s]? Seems
	// theoretical at best, and doesn't fit into the
	// current ServeHTTP model anyway. We'd need to
	// make the ResponseWriter an optional
	// "ExpectReplier" interface or something.
	//
	// For now we'll just obey RFC 7231 5.1.1 which says
	// "A server that receives an Expect field-value other
	// than 100-continue MAY respond with a 417 (Expectation
	// Failed) status code to indicate that the unexpected
	// expectation cannot be met."
	w.Header().Set("Connection", "close")
	w.WriteHeader(http.StatusExpectationFailed)
	w.finishRequest()
}

func (w *response) finalTrailers() http.Header {
	fmt.Println("response finalTrailers")
	var t http.Header
	for k, vv := range w.handlerHeader {
		if kk, found := strings.CutPrefix(k, http.TrailerPrefix); found {
			if t == nil {
				t = make(http.Header)
			}
			t[kk] = vv
		}
	}
	for _, k := range w.trailers {
		if t == nil {
			t = make(http.Header)
		}
		for _, v := range w.handlerHeader[k] {
			t.Add(k, v)
		}
	}
	return t
}

func (w *response) Header() http.Header {
	fmt.Println("response header")
	return w.handlerHeader
}

func (w *response) Write(data []byte) (int, error) {
	fmt.Println("response write")
	// 将数据写入到 TCP 连接
	return w.write(len(data), data, "")
}

func (w *response) WriteString(data string) (n int, err error) {
	return w.write(len(data), nil, data)
}

// either dataB or dataS is non-zero.
func (w *response) write(lenData int, dataB []byte, dataS string) (n int, err error) {

	if w.canWriteContinue.Load() {
		// Body reader wants to write 100 Continue but hasn't yet. Tell it not to.
		w.disableWriteContinue()
	}

	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}
	if lenData == 0 {
		return 0, nil
	}
	if !w.bodyAllowed() {
		return 0, http.ErrBodyNotAllowed
	}

	w.written += int64(lenData) // ignoring errors, for errorKludge
	if w.contentLength != -1 && w.written > w.contentLength {
		return 0, http.ErrContentLength
	}
	if dataB != nil {
		return w.w.Write(dataB)
	} else {
		return w.w.WriteString(dataS)
	}
}

// bodyAllowed reports whether a Write is allowed for this response type.
// It's illegal to call this before the header has been flushed.
func (w *response) bodyAllowed() bool {
	if !w.wroteHeader {
		panic("")
	}
	return bodyAllowedForStatus(w.status)
}

func (w *response) WriteHeader(code int) {
	fmt.Println("response writeHeader")
	if w.wroteHeader {
		caller := relevantCaller()
		fmt.Printf("http: superfluous response.WriteHeader call from %s (%s:%d)", caller.Function, path.Base(caller.File), caller.Line)
		return
	}
	checkWriteHeaderCode(code)

	if code < 101 || code > 199 {
		// Sending a 100 Continue or any non-1xx header disables the
		// automatically-sent 100 Continue from Request.Body.Read.
		w.disableWriteContinue()
	}

	// Handle informational handlerHeader.
	//
	// We shouldn't send any further handlerHeader after 101 Switching Protocols,
	// so it takes the non-informational path.
	if code >= 100 && code <= 199 && code != http.StatusSwitchingProtocols {
		writeStatusLine(w.conn.bufWriter, w.req.ProtoAtLeast(1, 1), code, w.statusBuf[:])

		// Per RFC 8297 we must not clear the current header map
		w.handlerHeader.WriteSubset(w.conn.bufWriter, map[string]bool{"Content-Length": true, "Transfer-Encoding": true})
		w.conn.bufWriter.Write(crlf)
		w.conn.bufWriter.Flush()

		return
	}

	w.wroteHeader = true
	w.status = code

	if w.calledHeader && w.cw.header == nil {
		w.cw.header = w.handlerHeader.Clone()
	}

	if cl := w.handlerHeader.Get("Content-Length"); cl != "" {
		v, err := strconv.ParseInt(cl, 10, 64)
		if err == nil && v >= 0 {
			w.contentLength = v
		} else {
			fmt.Printf("http: invalid Content-Length of %q", cl)
			w.handlerHeader.Del("Content-Length")
		}
	}
}

func (w *response) disableWriteContinue() {
	w.writeContinueMu.Lock()
	w.canWriteContinue.Store(false)
	w.writeContinueMu.Unlock()
}

type checkConnErrorWriter struct {
	c *conn
}

func (w checkConnErrorWriter) Write(p []byte) (n int, err error) {
	n, err = w.c.rwc.Write(p)
	if err != nil && w.c.werr == nil {
		w.c.werr = err
		w.c.cancelCtx()
	}
	return
}

func numLeadingCRorLF(v []byte) (n int) {
	for _, b := range v {
		if b == '\r' || b == '\n' {
			n++
			continue
		}
		break
	}
	return
}

// unsupportedTEError reports unsupported transfer-encodings.
type unsupportedTEError struct {
	err string
}

func (uste *unsupportedTEError) Error() string {
	return uste.err
}

// isUnsupportedTEError checks if the error is of type
// unsupportedTEError. It is usually invoked with a non-nil err.
func isUnsupportedTEError(err error) bool {
	var unsupportedTEError *unsupportedTEError
	ok := errors.As(err, &unsupportedTEError)
	return ok
}

type closeWriter interface {
	CloseWrite() error
}

var _ closeWriter = (*net.TCPConn)(nil)

func isCommonNetReadError(err error) bool {
	if err == io.EOF {
		return true
	}
	var neterr net.Error
	if errors.As(err, &neterr) && neterr.Timeout() {
		return true
	}
	var oe *net.OpError
	if errors.As(err, &oe) && oe.Op == "read" {
		return true
	}
	return false
}

type statusError struct {
	code int
	text string
}

func (e statusError) Error() string { return http.StatusText(e.code) + ": " + e.text }

func (w *response) finishRequest() {
	fmt.Println("response finishRequest")
	w.handlerDone.Store(true)

	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}

	w.w.Flush()
	putBufWriter(w.w)
	w.cw.close()
	w.conn.bufWriter.Flush()

	w.conn.r.abortPendingRead()
	// Close the body (regardless of w.closeAfterReply) so we can
	// re-use its bufio.Reader later safely.
	if w.reqBody != nil {
		w.reqBody.Close()
	}

	if w.req.MultipartForm != nil {
		w.req.MultipartForm.RemoveAll()
	}
}

func writeStatusLine(bw *bufio.Writer, is11 bool, code int, scratch []byte) {
	if is11 {
		bw.WriteString("HTTP/1.1 ")
	} else {
		bw.WriteString("HTTP/1.0 ")
	}
	if text := http.StatusText(code); text != "" {
		bw.Write(strconv.AppendInt(scratch[:0], int64(code), 10))
		bw.WriteByte(' ')
		bw.WriteString(text)
		bw.WriteString("\r\n")
	} else {
		// don't worry about performance
		fmt.Fprintf(bw, "%03d status code %d\r\n", code, code)
	}
}

func relevantCaller() runtime.Frame {
	pc := make([]uintptr, 16)
	n := runtime.Callers(1, pc)
	frames := runtime.CallersFrames(pc[:n])
	var frame runtime.Frame
	for {
		frame, more := frames.Next()
		if !strings.HasPrefix(frame.Function, "net/http.") {
			return frame
		}
		if !more {
			break
		}
	}
	return frame
}

func checkWriteHeaderCode(code int) {
	// Issue 22880: require valid WriteHeader status codes.
	// For now we only enforce that it's three digits.
	// In the future we might block things over 599 (600 and above aren't defined
	// at https://httpwg.org/specs/rfc7231.html#status.codes).
	// But for now any three digits.
	//
	// We used to send "HTTP/1.1 000 0" on the wire in responses but there's
	// no equivalent bogus thing we can realistically send in HTTP/2,
	// so we'll consistently panic instead and help people find their bugs
	// early. (We can't return an error from WriteHeader even if we wanted to.)
	if code < 100 || code > 999 {
		panic(fmt.Sprintf("invalid WriteHeader code %v", code))
	}
}

func bodyAllowedForStatus(status int) bool {
	switch {
	case status >= 100 && status <= 199:
		return false
	case status == 204:
		return false
	case status == 304:
		return false
	}
	return true
}

func startTCPServer(addr string, ginEngine *gin.Engine) {
	// 启动 TCP 监听服务
	listen, err := net.Listen("tcp", addr)
	if err != nil {
		fmt.Println("Error starting TCP server:", err)
		os.Exit(1)
	}
	defer listen.Close()

	fmt.Println(fmt.Sprintf("TCP server listening on %s", addr))
	for {
		// 接受客户端连接
		rw, err := listen.Accept()
		if err != nil {
			fmt.Println("Error accepting connection:", err)
			continue
		}
		c := &conn{
			rwc:     rw,
			Handler: ginEngine,
		}
		c.setState(c.rwc, http.StateNew, true) // before Serve can return
		// 将 TCP 连接交给 Gin 处理
		go c.handleTCPConnection(context.Background())
	}
}
