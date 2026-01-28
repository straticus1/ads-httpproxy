package proxy

import (
	"path/filepath"
	"strings"

	"ads-httpproxy/internal/scripting/starlark"
	"ads-httpproxy/internal/scripting/tengo"
	"ads-httpproxy/pkg/logging"

	"github.com/fsnotify/fsnotify"
	"go.uber.org/zap"
)

// StartHotReloadWatcher monitors the script file for changes and reloads the engine
func (s *Server) StartHotReloadWatcher(scriptPath string) {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		logging.Logger.Error("Failed to create file watcher", zap.Error(err))
		return
	}

	go func() {
		defer watcher.Close()
		for {
			select {
			case event, ok := <-watcher.Events:
				if !ok {
					return
				}
				if event.Has(fsnotify.Write) || event.Has(fsnotify.Create) {
					logging.Logger.Info("Script file modified, reloading...", zap.String("file", scriptPath))
					s.reloadScript(scriptPath)
				}
			case err, ok := <-watcher.Errors:
				if !ok {
					return
				}
				logging.Logger.Error("Watcher error", zap.Error(err))
			}
		}
	}()

	// Watch the directory of the file, because editors often rename/swap files
	dir := filepath.Dir(scriptPath)
	if err := watcher.Add(dir); err != nil {
		logging.Logger.Error("Failed to watch script directory", zap.Error(err))
	} else {
		logging.Logger.Info("Hot-reload watcher started", zap.String("dir", dir))
	}
}

func (s *Server) reloadScript(path string) {
	var err error
	if strings.HasSuffix(path, ".star") {
		s.scriptEngine, err = starlark.NewEngine(path)
	} else {
		s.scriptEngine, err = tengo.NewEngine(path)
	}

	if err != nil {
		logging.Logger.Error("Failed to reload script engine", zap.Error(err))
	} else {
		logging.Logger.Info("Script engine reloaded successfully")
	}
}
