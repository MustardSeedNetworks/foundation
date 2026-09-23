package api

// A handler that switches on r.Method mentions no registration call.
func (s *Server) routes() {
	s.routes.RegisterAll([]route.Route{
		{Path: "/api/v1/topology", Handler: s.handleTopology, Methods: []string{"GET"}, Auth: true},
	})
}
