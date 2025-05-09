package middleware

import (
	"github.com/casbin/casbin/v2"
	"github.com/cyber-xxm/cyber-gin/v1/pkg/errors"
	"github.com/cyber-xxm/cyber-gin/v1/pkg/util"
	"github.com/gin-gonic/gin"
)

var ErrCasbinDenied = errors.Forbidden("com.casbin.denied", "Permission denied")

type CasbinConfig struct {
	AllowedPathPrefixes []string
	SkippedPathPrefixes []string
	Skipper             func(c *gin.Context) bool
	GetEnforcer         func(c *gin.Context) *casbin.Enforcer
	GetSubjects         func(c *gin.Context) []string
}

func CasbinWithConfig(config CasbinConfig) gin.HandlerFunc {
	return func(c *gin.Context) {
		if !AllowedPathPrefixes(c, config.AllowedPathPrefixes...) ||
			SkippedPathPrefixes(c, config.SkippedPathPrefixes...) ||
			(config.Skipper != nil && config.Skipper(c)) {
			c.Next()
			return
		}

		enforcer := config.GetEnforcer(c)
		if enforcer == nil {
			util.ResError(c, ErrCasbinDenied)
			return
		}

		for _, sub := range config.GetSubjects(c) {
			if b, err := enforcer.Enforce(sub, c.Request.URL.Path, c.Request.Method); err != nil {
				util.ResError(c, err)
				return
			} else if b {
				c.Next()
				return
			}
		}
		util.ResError(c, ErrCasbinDenied)
	}
}
