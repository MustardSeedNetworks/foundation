package api

func registerDebug(pattern string) { http.HandleFunc(pattern, debugHandler) }
