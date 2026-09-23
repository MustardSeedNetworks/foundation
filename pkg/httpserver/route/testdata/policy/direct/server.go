package api

func (s *Server) setup() {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/reflector/config", s.handleReflectorConfig)
}
