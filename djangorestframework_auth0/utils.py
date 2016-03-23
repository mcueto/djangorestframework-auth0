def auth0_get_username_from_payload_handler(payload):
    # print("get auth0 user")
    return payload.get('sub')
