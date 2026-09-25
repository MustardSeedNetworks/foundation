package api

func (s *Server) legacy(mux *http.ServeMux) {
	mux.Handle(`/api/v1/legacy`, s.handleLegacy())
}
