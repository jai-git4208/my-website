import smtplib

EMAIL_ADDRESS = "jaiminpansal@gmail.com"
EMAIL_PASSWORD = "jaiminisop@69"

try:
    server = smtplib.SMTP('smtp.gmail.com', 587)
    server.starttls()
    server.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
    print("Login successful!")
    server.quit()
except Exception as e:
    print("Error:", e)
