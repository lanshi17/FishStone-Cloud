# tests/test_integration.py
def test_user_registration_and_login(client):
    # 注册新用户
    client.post('/register', data={
        'username': 'newuser',
        'email': 'new@example.com',
        'password': 'testpass',
        'confirm_password': 'testpass'
    })
    # 使用新注册的用户登录
    response = client.post('/login', data={
        'username': 'newuser',
        'password': 'testpass'
    }, follow_redirects=True)
    assert 'Welcome to the Dashboard' in response.get_data(as_text=True)
