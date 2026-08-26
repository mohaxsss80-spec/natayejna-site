import os
import subprocess
import time

print("جاري تشغيل النفق السحري المقاوم للحظر...")
time.sleep(1)

# تشغيل نفق مستقر يتخطى حظر الشبكة
os.system("ssh -o StrictHostKeyChecking=no -R 80:127.0.0.1:5000 nokey@localhost.run")
