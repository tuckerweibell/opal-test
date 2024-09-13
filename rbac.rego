package rbac

import data.team_emails as allowed_emails

default allow = false

allow {
	startswith(input.request.path, "/admin")
	allowed_emails[_] == input.email
}

allow {
	not startswith(input.request.path, "/admin")
}