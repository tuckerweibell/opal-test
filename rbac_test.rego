package rbac_test

import data.rbac.allow

test_allow_admin_access_if_team_member {
    allow with input as {
        "request": {
            "path": "/admin",
        },
        "email": "test@test.com",
    }
    allow with input as {
        "request": {
            "path": "/admin/panel",
        },
        "email": "test@test.com",
    }
}

test_allow_admin_access_if_team_member {
    not allow with input as {
        "request": {
            "path": "/admin",
        },
        "email": "not-admin@test.com",
    }
    not allow with input as {
        "request": {
            "path": "/admin/panel",
        },
        "email": "not-admin@test.com",
    }
}

test_allow_all_paths_if_not_admin_path {
    allow with input as {
        "request": {
            "path": "/recommended_actions",
        },
        "email": "not-admin@test.com",
    }
    allow with input as {
        "request": {
            "path": "/team/1",
        },
        "email": "not-admin@test.com",
    }
    allow with input as {
        "request": {
            "path": "/team/2/recommended_actions/",
        },
        "email": "not-admin@test.com",
    }
}


