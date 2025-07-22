from rubka import Robot
from rubka.context import Message
import validators
import tldextract
import requests
import certifi

class PhishingDetector:
    def __init__(self, token: str):
        self.bot = Robot(token=token)

        
        self.trusted_domains = {
            
    "instagram.com",
    "facebook.com",
    "twitter.com",
    "linkedin.com",
    "t.me",
    "threads.net",
    "discord.com",
    "snapchat.com",
    "whatsapp.com",
    'web.rubika.ir',
    'rubika.ir',
    "eitaa.com",         # پیغام‌رسان ایتا :contentReference[oaicite:1]{index=1}
    "splus.ir",   
    "bale.ai",           # بله
    "gap.im",            # گپ
    "igap.net",          # آی‌گپ :contentReference[oaicite:4]{index=4}
    "wispi.ir",          # ویسپی
    "bisphone.ir",       # بیسفون
    "chatzi.ir",         # چتزی
    "novachat.ir",       # نوا
    "hedhed.ir",         # هدهد
    "ring.ir",           # رینگ
    "balont.ir",         # بالونت  

    # 📧 سرویس‌های ایمیل و کلاد
    "gmail.com",
    "mail.google.com",
    "outlook.com",
    "live.com",
    "yahoo.com",
    "icloud.com",
    "protonmail.com",
    "zoho.com",

    # 💳 فروشگاه‌ها و خدمات پرداخت بین‌المللی
    "amazon.com",
    "paypal.com",
    "stripe.com",
    "aliexpress.com",
    "ebay.com",
    "apple.com",
    "microsoft.com",
    "netflix.com",

    # 🔍 گوگل و خدماتش
    "google.com",
    "youtube.com",
    "drive.google.com",
    "docs.google.com",
    "maps.google.com",
    "accounts.google.com",

    # 👨‍💻 ابزارهای برنامه‌نویسی
    "github.com",
    "gitlab.com",
    "bitbucket.org",
    "stackoverflow.com",
    "npmjs.com",
    "pypi.org",

    # 🧠 هوش مصنوعی و امنیت
    "openai.com",
    "huggingface.co",
    "virustotal.com",
    "haveibeenpwned.com",

    # 📱 مارکت‌های اپلیکیشن
    "play.google.com",
    "apps.apple.com",
    "f-droid.org",
    "apkpure.com",
    "apkcombo.com",

    # ⚖️ سایت‌های رسمی ایرانی (دولتی، قضایی، اطلاع‌رسانی)
    "sana.adliran.ir",       # سامانه ثنا قوه قضائیه
    "adliran.ir",            # قوه قضائیه
    "my.gov.ir",             # درگاه خدمات دولت
    "shekayat.maj.ir",       # مجلس - سامانه شکایات
    "epolice.ir",            # پلیس راهور
    "ecsw.ir",               # مرکز توسعه تجارت الکترونیکی (نماد اعتماد)
    "iran.ir",               # درگاه ملی خدمات دولت هوشمند
    "eblagh.adliran.ir",     # سامانه ابلاغیه الکترونیکی
    "sabteahval.ir",         # ثبت احوال

    # 💰 بانک‌ها و سامانه‌های پرداخت ایرانی
    "bmi.ir",                # بانک ملی
    "banksepah.ir",          # بانک سپه
    "bankmellat.ir",         # بانک ملت
    "bsi.ir",                # بانک صادرات
    "bimeh.com",             # بیمه مرکزی ایران
    "shaparak.ir",           # شبکه شاپرک
    "mellatbank.com",
    "bankpasargad.com",
    "sb24.ir",               # بانک سامان
    "bank-day.ir",           # بانک دی
    "bank-refah.ir",         # بانک رفاه
    "bank-maskan.ir",        # بانک مسکن
    "bank-sina.com",
    "tejaratbank.ir",

    # 🖥️ سامانه‌های خدماتی رسمی ایرانی
    "my.iranic.ir",          # ایرنیک
    "rahvar120.ir",          # پلیس +120
    "moi.ir",                # وزارت کشور
    "iranpost.ir",           # پست جمهوری اسلامی
    "sms.gov.ir",            # سامانه پیامکی دولتی

    # 🕋 سایت‌های فرهنگی و مذهبی
    "leader.ir",             # سایت رهبری
    "khamenei.ir",           # پایگاه اطلاع‌رسانی رهبری
    "hawzah.net",
    "iribnews.ir",           # خبرگزاری صداوسیما
    "isna.ir",               # خبرگزاری ایسنا
        }

        self.bot.on_message()(self.handle_message)

    def is_ssl_valid(self, url: str) -> bool:
        """بررسی SSL با درخواست GET ایمن"""
        try:
            response = requests.get(url, timeout=10, verify=certifi.where(), allow_redirects=True)
            return response.status_code < 400
        except Exception:
            return False

    def extract_domain(self, url: str) -> str:
        """استخراج دامنه سطح بالا"""
        ext = tldextract.extract(url)
        return f"{ext.domain}.{ext.suffix}"

    def is_trusted(self, domain: str) -> bool:
       
        return domain in self.trusted_domains

    def handle_message(self, bot: Robot, message: Message):
        text = message.text.strip() if message.text else ""

        if text.lower() == "/start":
            bot.send_message(
                chat_id=message.chat_id,
                text="🌐 خوش آمدید به ربات فیشینگ‌یاب و لینک‌مخرب‌سنج!\n"
                     "فقط کافیست یک لینک بفرستید تا بررسی شود ✅"
            )
            return

        if text.startswith("http://") or text.startswith("https://"):
            bot.send_message(chat_id=message.chat_id, text="🔍 در حال بررسی لینک ارسالی...")

            if not validators.url(text):
                bot.send_message(chat_id=message.chat_id, text="❌ لینک معتبر نیست. لطفاً آدرس درست وارد کنید.")
                return

            domain = self.extract_domain(text)
            ssl_valid = self.is_ssl_valid(text)
            trusted = self.is_trusted(domain)

            # ساخت پاسخ بر اساس وضعیت لینک
            if trusted and ssl_valid:
                response = (
                    f"✅ لینک کاملاً معتبر است.\n"
                    f"🌐 دامنه: {domain}\n"
                    f"🔒 دارای گواهی SSL معتبر ✅"
                )
            elif trusted and not ssl_valid:
                response = (
                    f"⚠️ دامنه در لیست معتبرها هست اما اتصال امن (SSL) ندارد یا مشکلی دارد.\n"
                    f"🌐 دامنه: {domain}"
                )
            elif not trusted and ssl_valid:
                response = (
                    f"⚠️ لینک دارای SSL هست اما دامنه در لیست معتبر نیست.\n"
                    f"🌐 دامنه مشکوک: {domain}\n"
                    f"⚠️ توصیه می‌شود با احتیاط وارد این لینک شوید."
                )
            else:
                response = (
                    f"🚫 لینک مشکوک تشخیص داده شد!\n"
                    f"🌐 دامنه: {domain}\n"
                    f"❌ نه SSL معتبر دارد و نه دامنه‌ای مطمئن است.\n"
                    f"⚠️ احتمال فیشینگ بسیار بالاست."
                )

            bot.send_message(chat_id=message.chat_id, text=response)

    def run(self):
        self.bot.run()


if __name__ == "__main__":
    token= "token to"
    detector_bot = PhishingDetector(token=token)
    detector_bot.run()
