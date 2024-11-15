package rbac

type Service struct {
	ID    string  `json:"id"`
	Name  string  `json:"name"`
	Roles []*Role `json:"roles,omitempty"`
}

const DefaultServiceID string = "default"

var CurrentService *Service
