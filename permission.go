package rbac

type Permissions struct {
	Create     bool `json:"create"`
	SelfCreate bool `json:"self-create"`
	Read       bool `json:"read"`
	SelfRead   bool `json:"self-read"`
	Update     bool `json:"update"`
	SelfUpdate bool `json:"self-update"`
	Delete     bool `json:"delete"`
	SelfDelete bool `json:"self-delete"`
}
