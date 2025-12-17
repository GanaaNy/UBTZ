# Төмөр замын түүхий эдийн хадгалалт, зарцуулалтын бүртгэлийн систем
# (Raw material storage and usage record system)

# Төслийн зорилго
УБТЗамын ангиудын өдөр тутам гараар бичдэг тайлан, бүртгэлийг цахимд шилжүүлэх. Сарын сүүлд гаргах ерөнхий тайланг автоматаар гаргадаг болгох. Ингэснээр мастер болон нягтлангийн ажлыг хөнгөвчлөх.

# Хамрах хүрээ
УБТЗамын ангиуд

# Хэрэглэгч
УБТЗамын ажилчид (мастер, нягтлангууд)

# Суулгах заавар

## Backend суулгах
```bash
cd backend
pip install -r requirements.txt
python login.py
```

Backend сервер `http://localhost:5000` дээр ажиллана.

## Frontend ажиллуулах
`login.html` файлыг браузер дээр нээх эсвэл local web server ашиглах.

## Туршилтын хэрэглэгчид
- **admin** / admin123
- **master** / master123
- **accountant** / accountant123

## Unit тест ажиллуулах

### Бүх тестийг ажиллуулах
```bash
cd backend
pytest test_login.py -v
```

### Тодорхой тест класс ажиллуулах
```bash
pytest test_login.py::TestLoginEndpoint -v
```

### Тодорхой тест функц ажиллуулах
```bash
pytest test_login.py::TestLoginEndpoint::test_successful_login_admin -v
```

### Тест coverage-тай ажиллуулах
```bash
pytest test_login.py --cov=login --cov-report=html
```

## Тест файлууд
- `test_login.py` - Login функцлэлийн бүх unit тестүүд
- `pytest.ini` - Pytest тохиргоо
- `run_tests.py` - Тест ажиллуулах энгийн скрипт