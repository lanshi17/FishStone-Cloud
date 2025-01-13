from app.models.models import User

def test_new_user():
    user = User(username='testuser', email='test@example.com')
    user.set_password('123456')
    assert user.username == 'testuser'
    assert user.check_password('123456') == True
    assert user.check_password('wrongpassword') == False
