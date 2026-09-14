package proxy

import (
	"path/filepath"

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

	dir := filepath.Dir(scriptPath)
	if err := watcher.Add(dir); err != nil {
		watcher.Close()
		logging.Logger.Error("Failed to watch script directory", zap.Error(err))
		return
	}
	s.scriptWatcher = watcher
	go func() {
		defer watcher.Close()
		for {
			select {
			case event, ok := <-watcher.Events:
				if !ok {
					return
				}
				if (event.Has(fsnotify.Write) || event.Has(fsnotify.Create)) && filepath.Clean(event.Name) == filepath.Clean(scriptPath) {
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

}

func (s *Server) reloadScript(path string) {
	reloader, ok := s.scriptEngine.(interface{ Reload() error })
	if !ok {
		return
	}
	if err := reloader.Reload(); err != nil {
		logging.Logger.Error("Failed to reload script engine", zap.Error(err))
	} else {
		logging.Logger.Info("Script engine reloaded successfully")
	}
}
