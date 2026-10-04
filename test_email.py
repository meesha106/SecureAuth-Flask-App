import smtplib
server = smtplib.SMTP('smtp.gmail.com', 587)
server.starttls()
server.login("meesha2305@gmail.com", "xkcjhcvginitdlgq")
print("Login successful")
server.quit()