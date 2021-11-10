# Install requirements
- In `code` folder
```bash
python -m venv venv
source venv/bin/activate
pip3 install -r requirements.txt
```

# Run
- In `code` folder

1- Helper application

```bash
python3 -m helper.helper_application # 0.0.0.0:8083
```

2- SP

```bash
python3 -m sp.SP # 0.0.0.0:8081
```

3- IDP

```bash
python3 -m idp.IdP # 0.0.0.0:8082
```
