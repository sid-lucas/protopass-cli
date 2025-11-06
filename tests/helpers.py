class DummyResponse:
    """
    Imite le sous-ensemble de requests-response utilisé par le client.
    """

    def __init__(self, flask_response):
        self._resp = flask_response
        self.status_code = flask_response.status_code

    def json(self):
        return self._resp.get_json()


def build_fake_api_post(client):
    """
    Retourne un appelable qui reproduit api_post en passant par un client Flask de test.
    """

    def fake_api_post(endpoint, payload=None, user=None):
        response = client.post(endpoint, json=payload)
        return DummyResponse(response)

    return fake_api_post
