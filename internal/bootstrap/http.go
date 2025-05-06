package bootstrap

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	er "errors"
	"fmt"
	"gitee.com/Trisia/gotlcp/tlcp"
	"github.com/casbin/casbin/v2"
	"github.com/cyber-xxm/cyber-gin/v1/internal/config"
	"github.com/cyber-xxm/cyber-gin/v1/internal/utility/prom"
	"github.com/cyber-xxm/cyber-gin/v1/internal/wirex"
	"github.com/cyber-xxm/cyber-gin/v1/pkg/errors"
	"github.com/cyber-xxm/cyber-gin/v1/pkg/logging"
	"github.com/cyber-xxm/cyber-gin/v1/pkg/middleware"
	"github.com/cyber-xxm/cyber-gin/v1/pkg/util"
	"github.com/emmansun/gmsm/smx509"
	"github.com/gin-gonic/gin"
	swaggerFiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"
	"go.uber.org/zap"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

func startHTTPServer(ctx context.Context, injector *wirex.Injector) (func(), error) {
	if config.C.IsDebug() {
		gin.SetMode(gin.DebugMode)
	} else {
		gin.SetMode(gin.ReleaseMode)
	}

	e := gin.New()
	e.GET("/health", func(c *gin.Context) {
		util.ResOK(c)
	})
	e.Use(middleware.RecoveryWithConfig(middleware.RecoveryConfig{
		Skip: config.C.Middleware.Recovery.Skip,
	}))
	e.NoMethod(func(c *gin.Context) {
		util.ResError(c, errors.MethodNotAllowed("", "Method Not Allowed"))
	})
	e.NoRoute(func(c *gin.Context) {
		util.ResError(c, errors.NotFound("", "Not Found"))
	})

	allowedPrefixes := injector.M.RouterPrefixes()

	// Register middlewares
	if err := useHTTPMiddlewares(ctx, e, injector, allowedPrefixes); err != nil {
		return nil, err
	}

	// Register routers
	if err := injector.M.RegisterRouters(ctx, e); err != nil {
		return nil, err
	}

	// Register swagger
	if !config.C.General.DisableSwagger {
		e.StaticFile("/openapi.json", filepath.Join(config.C.General.WorkDir, "openapi.json"))
		e.GET("/swagger/*any", ginSwagger.WrapHandler(swaggerFiles.Handler))
	}

	if dir := config.C.Middleware.Static.Dir; dir != "" {
		e.Use(middleware.StaticWithConfig(middleware.StaticConfig{
			Root:                dir,
			SkippedPathPrefixes: allowedPrefixes,
		}))
	}

	addr := config.C.General.HTTP.Addr
	logging.Context(ctx).Info(fmt.Sprintf("server is listening on %s", addr))

	srv := &http.Server{}
	tlsConfig, err := loadTLSCerts(ctx)
	if err != nil {
		logging.Context(ctx).Error("Failed to load certs ", zap.Error(err))
		return nil, err
	}
	tlcpConfig, err := loadTLCPCerts(ctx)
	if err != nil {
		logging.Context(ctx).Error("Failed to load certs ", zap.Error(err))
		return nil, err
	}

	// 判断是否同时配置了tls和tlcp证书，如果是，则报错
	if tlsConfig != nil && tlcpConfig != nil {
		return nil, er.New("do not use TLS and TLCP both")
	}

	go func() {
		// 如果是起http服务
		if !config.C.General.HTTP.EnableTcp {
			srv.Addr = addr
			srv.Handler = e
			srv.ReadTimeout = time.Second * time.Duration(config.C.General.HTTP.ReadTimeout)
			srv.WriteTimeout = time.Second * time.Duration(config.C.General.HTTP.WriteTimeout)
			srv.IdleTimeout = time.Second * time.Duration(config.C.General.HTTP.IdleTimeout)
			// 如果是起https服务
			if tlsConfig != nil {
				srv.TLSConfig = tlsConfig
				err = srv.ListenAndServeTLS("", "")
			} else {
				err = srv.ListenAndServe()
			}
		} else {
			err = startTCPServer(addr, tlsConfig, tlcpConfig, e)
		}
		if err != nil && !er.Is(http.ErrServerClosed, err) {
			logging.Context(ctx).Error("Failed to listen http server", zap.Error(err))
		}
	}()
	return func() {
		ctx, cancel := context.WithTimeout(ctx, time.Second*time.Duration(config.C.General.HTTP.ShutdownTimeout))
		defer cancel()

		srv.SetKeepAlivesEnabled(false)
		if err := srv.Shutdown(ctx); err != nil {
			logging.Context(ctx).Error("Failed to shutdown http server", zap.Error(err))
		}
	}, nil
}

func useHTTPMiddlewares(_ context.Context, e *gin.Engine, injector *wirex.Injector, allowedPrefixes []string) error {
	e.Use(middleware.CORSWithConfig(middleware.CORSConfig{
		Enable:                 config.C.Middleware.CORS.Enable,
		AllowAllOrigins:        config.C.Middleware.CORS.AllowAllOrigins,
		AllowOrigins:           config.C.Middleware.CORS.AllowOrigins,
		AllowMethods:           config.C.Middleware.CORS.AllowMethods,
		AllowHeaders:           config.C.Middleware.CORS.AllowHeaders,
		AllowCredentials:       config.C.Middleware.CORS.AllowCredentials,
		ExposeHeaders:          config.C.Middleware.CORS.ExposeHeaders,
		MaxAge:                 config.C.Middleware.CORS.MaxAge,
		AllowWildcard:          config.C.Middleware.CORS.AllowWildcard,
		AllowBrowserExtensions: config.C.Middleware.CORS.AllowBrowserExtensions,
		AllowWebSockets:        config.C.Middleware.CORS.AllowWebSockets,
		AllowFiles:             config.C.Middleware.CORS.AllowFiles,
	}))

	e.Use(middleware.TraceWithConfig(middleware.TraceConfig{
		AllowedPathPrefixes: allowedPrefixes,
		SkippedPathPrefixes: config.C.Middleware.Trace.SkippedPathPrefixes,
		RequestHeaderKey:    config.C.Middleware.Trace.RequestHeaderKey,
		ResponseTraceKey:    config.C.Middleware.Trace.ResponseTraceKey,
	}))

	e.Use(middleware.LoggerWithConfig(middleware.LoggerConfig{
		AllowedPathPrefixes:      allowedPrefixes,
		SkippedPathPrefixes:      config.C.Middleware.Logger.SkippedPathPrefixes,
		MaxOutputRequestBodyLen:  config.C.Middleware.Logger.MaxOutputRequestBodyLen,
		MaxOutputResponseBodyLen: config.C.Middleware.Logger.MaxOutputResponseBodyLen,
	}))

	e.Use(middleware.CopyBodyWithConfig(middleware.CopyBodyConfig{
		AllowedPathPrefixes: allowedPrefixes,
		SkippedPathPrefixes: config.C.Middleware.CopyBody.SkippedPathPrefixes,
		MaxContentLen:       config.C.Middleware.CopyBody.MaxContentLen,
	}))

	e.Use(middleware.AuthWithConfig(middleware.AuthConfig{
		AllowedPathPrefixes: allowedPrefixes,
		SkippedPathPrefixes: config.C.Middleware.Auth.SkippedPathPrefixes,
		ParseUserID:         injector.M.RBAC.LoginAPI.LoginBIZ.ParseUserID,
		RootID:              config.C.General.Root.ID,
	}))

	e.Use(middleware.RateLimiterWithConfig(middleware.RateLimiterConfig{
		Enable:              config.C.Middleware.RateLimiter.Enable,
		AllowedPathPrefixes: allowedPrefixes,
		SkippedPathPrefixes: config.C.Middleware.RateLimiter.SkippedPathPrefixes,
		Period:              config.C.Middleware.RateLimiter.Period,
		MaxRequestsPerIP:    config.C.Middleware.RateLimiter.MaxRequestsPerIP,
		MaxRequestsPerUser:  config.C.Middleware.RateLimiter.MaxRequestsPerUser,
		StoreType:           config.C.Middleware.RateLimiter.Store.Type,
		MemoryStoreConfig: middleware.RateLimiterMemoryConfig{
			Expiration:      time.Second * time.Duration(config.C.Middleware.RateLimiter.Store.Memory.Expiration),
			CleanupInterval: time.Second * time.Duration(config.C.Middleware.RateLimiter.Store.Memory.CleanupInterval),
		},
		RedisStoreConfig: middleware.RateLimiterRedisConfig{
			Addr:     config.C.Middleware.RateLimiter.Store.Redis.Addr,
			Password: config.C.Middleware.RateLimiter.Store.Redis.Password,
			DB:       config.C.Middleware.RateLimiter.Store.Redis.DB,
			Username: config.C.Middleware.RateLimiter.Store.Redis.Username,
		},
	}))

	e.Use(middleware.CasbinWithConfig(middleware.CasbinConfig{
		AllowedPathPrefixes: allowedPrefixes,
		SkippedPathPrefixes: config.C.Middleware.Casbin.SkippedPathPrefixes,
		Skipper: func(c *gin.Context) bool {
			if config.C.Middleware.Casbin.Disable ||
				util.FromIsRootUser(c.Request.Context()) {
				return true
			}
			return false
		},
		GetEnforcer: func(c *gin.Context) *casbin.Enforcer {
			return injector.M.RBAC.Casbinx.GetEnforcer()
		},
		GetSubjects: func(c *gin.Context) []string {
			return util.FromUserCache(c.Request.Context()).RoleIDs
		},
	}))

	if config.C.Util.Prometheus.Enable {
		e.Use(prom.GinMiddleware)
	}

	return nil
}

func loadTLSCerts(ctx context.Context) (*tls.Config, error) {
	if config.C.General.HTTP.CertFile != "" && config.C.General.HTTP.KeyFile != "" && config.C.General.HTTP.CaFile != "" {
		// 1. 加载服务器证书
		serverCert, err := tls.LoadX509KeyPair(config.C.General.HTTP.CertFile, config.C.General.HTTP.KeyFile)
		if err != nil {
			logging.Context(ctx).Info("failed to load server cert/key: %v", zap.Error(err))
			return nil, err
		}

		// 2. 加载CA，用来验证客户端证书
		caCert, err := os.ReadFile(config.C.General.HTTP.CaFile)
		if err != nil {
			logging.Context(ctx).Info("failed to read CA cert: %v", zap.Error(err))
			return nil, err
		}
		caCertPool := x509.NewCertPool()
		caCertPool.AppendCertsFromPEM(caCert)

		// 3. TLS配置，要求客户端提供证书并验证
		return &tls.Config{
			Certificates: []tls.Certificate{serverCert},
			ClientCAs:    caCertPool,
			ClientAuth:   tls.RequireAndVerifyClientCert,
			MinVersion:   tls.VersionTLS12,
		}, nil
	}
	return nil, nil
}

func loadTLCPCerts(ctx context.Context) (*tlcp.Config, error) {
	if config.C.General.HTTP.RootCertFile != "" &&
		config.C.General.HTTP.SigCertFile != "" &&
		config.C.General.HTTP.SigKeyFile != "" &&
		config.C.General.HTTP.EncCertFile != "" &&
		config.C.General.HTTP.EncKeyFile != "" {
		fileBytes, err := os.ReadFile(config.C.General.HTTP.RootCertFile)
		sigCertFileBytes, err := os.ReadFile(config.C.General.HTTP.SigCertFile)
		sigKeyFileBytes, err := os.ReadFile(config.C.General.HTTP.SigKeyFile)
		encCertFileBytes, err := os.ReadFile(config.C.General.HTTP.EncCertFile)
		encKeyFileBytes, err := os.ReadFile(config.C.General.HTTP.EncKeyFile)
		if err != nil {
			return nil, err
		}
		// 1. 加载服务器证书
		rootCert, err := smx509.ParseCertificatePEM(fileBytes)
		if err != nil {
			logging.Context(ctx).Info("failed to load server root cert/key: %v", zap.Error(err))
			return nil, err
		}

		// 2. 加载CA，用来验证客户端证书
		sigCertKey, err := tlcp.X509KeyPair(sigCertFileBytes, sigKeyFileBytes)
		if err != nil {
			logging.Context(ctx).Info("failed to read sig cert: %v", zap.Error(err))
			return nil, err
		}
		encCertKey, err := tlcp.X509KeyPair(encCertFileBytes, encKeyFileBytes)
		if err != nil {
			logging.Context(ctx).Info("failed to read enc cert: %v", zap.Error(err))
			return nil, err
		}
		pool := smx509.NewCertPool()
		pool.AddCert(rootCert)
		// 3. TLS配置，要求客户端提供证书并验证
		return &tlcp.Config{
			Certificates: []tlcp.Certificate{sigCertKey, encCertKey},
			ClientAuth:   tlcp.RequireAndVerifyClientCert,
			ClientCAs:    pool,
			CipherSuites: []uint16{
				tlcp.ECDHE_SM4_GCM_SM3, // 最高优先级
				tlcp.ECC_SM4_CBC_SM3,   // 最低优先级
			},
			// Time:        runtimeTime,
			EnableDebug: true,
		}, nil
	}
	return nil, nil
}
