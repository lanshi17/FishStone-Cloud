# tests/test_views.py
def test_login_page(client):
    response = client.get('/login')
    assert response.status_code == 200
    assert 'Login' in response.get_data(as_text=True)

def test_register(client):
    response = client.post('/register', data={
        'username': 'testuser',
        'email': 'test@example.com',
        'password': '123456',
        'confirm_password': '123456'
    }, follow_redirects=True)
    assert 'Congratulations, registration successful!' in response.get_data(as_text=True)
