# classical-cryptography-frequency-analysis
Classical cryptography and cryptanalysis project using Caesar, Substitution, and Vigenere ciphers with frequency analysis.
# پروژهٔ رمزنگاری کلاسیک

این پروژه برای درس ریاضیات گسسته تهیه شده و شامل پیاده‌سازی چهار روش رمزنگاری کلاسیک است:

- رمز سزار (Caesar Cipher)
- رمز جانشینی (Substitution Cipher)
- رمز ویژنر (Vigenère Cipher)
- رمز هیل (Hill Cipher)

هر بخش در پوشه‌ای مستقل قرار دارد و شامل کد اصلی، تست‌ها، داده‌های نمونه، مستندات و نتایج آزمایش‌ها است.

> این پروژه با هدف آموزش ساخته شده و برای محافظت از اطلاعات واقعی و حساس مناسب نیست.

## اعضای تیم

| همکار | بخش انجام‌شده | شاخه / مسیر |
|---|---|---|
| Parsa Tabatabaei | رمز جانشینی | `substitution` |
| Mohammadali Jafari | رمز سزار | `Caesar-kntu` |
| Parsa Hashemi | رمز ویژنر و رمز هیل | `vigenere_project` و `hill_project` |

شاخهٔ `main` شامل نسخهٔ نهایی و یکپارچهٔ پروژه است.

## امکانات پروژه

- رمزگذاری و رمزگشایی متن
- دریافت متن مستقیم یا خواندن از فایل
- رابط خط فرمان و منوی تعاملی
- شکستن بعضی رمزها بدون داشتن کلید
- تحلیل فراوانی حروف
- محاسبهٔ آنتروپی و سایر اطلاعات آماری
- تحلیل دوگرام‌ها و سه‌گرام‌ها
- اجرای آزمایش روی متن‌هایی با طول متفاوت
- تولید گزارش‌های CSV و JSON
- تولید نمودارهای PNG
- تست‌های خودکار

## ساختار پروژه

```text
.
├── Caesar-kntu/          # بخش رمز سزار
├── substitution/        # بخش رمز جانشینی
├── vigenere_project/    # بخش رمز ویژنر
├── hill_project/        # بخش رمز هیل
└── tmp/                 # فایل‌های موقت گزارش‌ها
```

ساختار کلی هر بخش به شکل زیر است:

```text
project/
├── src/                 # کدهای اصلی
├── tests/               # تست‌های خودکار
├── data/                # داده‌ها و متن‌های نمونه
├── benchmarks/          # نتایج آزمایش‌ها
├── docs/                # مستندات و گزارش‌ها
├── output/              # خروجی‌های تولیدشده
├── main.py              # فایل اصلی اجرا
├── requirements.txt     # وابستگی‌ها
└── README.md            # توضیحات اختصاصی بخش
```

## معرفی بخش‌ها

### رمز سزار

این بخش در پوشهٔ `Caesar-kntu` قرار دارد و امکانات زیر را ارائه می‌دهد:

- رمزگذاری و رمزگشایی با کلید عددی
- نمایش تمام حالت‌های ممکن
- تشخیص خودکار کلید
- تحلیل آماری متن
- مقایسهٔ روش‌های مختلف رمز‌شکنی
- اندازه‌گیری نرخ موفقیت و زمان اجرا
- تولید گزارش فارسی و نمودار

### رمز جانشینی

این بخش در پوشهٔ `substitution` قرار دارد و از متن‌های انگلیسی و فارسی پشتیبانی می‌کند.

امکانات اصلی آن عبارت‌اند از:

- تولید کلید تصادفی
- رمزگذاری و رمزگشایی
- شکستن رمز با تحلیل فراوانی
- حمله‌های Hill Climbing و Simulated Annealing
- تحلیل حروف، دوگرام‌ها و سه‌گرام‌ها
- مقایسهٔ آنتروپی متن اصلی و متن رمز
- محاسبهٔ دقت بازیابی

### رمز ویژنر

این بخش در پوشهٔ `vigenere_project` قرار دارد و شامل موارد زیر است:

- رمزگذاری و رمزگشایی با کلید متنی
- بررسی معتبر بودن کلید
- تخمین طول کلید
- بازیابی کلید و متن
- نمایش چند پاسخ احتمالی
- تحلیل آماری متن
- آزمایش نرخ موفقیت رمز‌شکنی

### رمز هیل

این بخش در پوشهٔ `hill_project` قرار دارد و شامل امکانات زیر است:

- رمزگذاری و رمزگشایی با ماتریس کلید
- بررسی معتبر بودن ماتریس
- پشتیبانی از اندازه‌های مختلف ماتریس
- مدیریت کامل نبودن بلوک آخر متن
- بازیابی کلید با داشتن نمونه‌ای از متن اصلی
- اجرای benchmark برای طول‌های مختلف متن

## پیش‌نیازها

برای اجرای پروژه به موارد زیر نیاز است:

- Python 3.10 یا جدیدتر
- pip
- Matplotlib برای تولید نمودارها
- pytest برای اجرای تست‌های بخش سزار

## نصب

ابتدا مخزن را دریافت کرده و وارد پوشهٔ پروژه شوید:

```powershell
git clone <repository-url>
cd "Discrete Mathematics"
```

ساخت محیط مجازی:

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
```

نصب وابستگی‌ها:

```powershell
python -m pip install -r Caesar-kntu/requirements.txt
python -m pip install -r substitution/requirements.txt
python -m pip install -r vigenere_project/requirements.txt
python -m pip install -r hill_project/requirements.txt
```

## اجرای پروژه

هر بخش دارای منوی تعاملی است. برای اجرای آن کافی است وارد پوشهٔ موردنظر شوید و `main.py` را اجرا کنید.

### رمز سزار

```powershell
cd Caesar-kntu
python main.py
```

نمونهٔ اجرای مستقیم:

```powershell
python main.py encrypt --text "Hello, World!" --key 3
python main.py decrypt --text "Khoor, Zruog!" --key 3
python main.py brute-force --text "Khoor, Zruog!"
python main.py crack --text "Khoor, Zruog!"
```

### رمز جانشینی

```powershell
cd substitution
python main.py
```

نمونهٔ اجرای مستقیم:

```powershell
python main.py generate-key --language en --seed 1405
python main.py encrypt --text "Hello world!" --key zyxwvutsrqponmlkjihgfedcba
python main.py decrypt --text "Svool dliow!" --key zyxwvutsrqponmlkjihgfedcba
```

شکستن رمز:

```powershell
python main.py break --language en --algorithm frequency --input output/ciphertext.txt
```

### رمز ویژنر

```powershell
cd vigenere_project
python main.py
```

نمونهٔ اجرای مستقیم:

```powershell
python main.py encrypt --text "Attack at dawn!" --key LEMON
python main.py decrypt --text "Lxfopv ef rnhr!" --key LEMON
python main.py break --input output/ciphertext.txt --max-key-length 15
```

### رمز هیل

```powershell
cd hill_project
python main.py
```

نمونهٔ اجرای مستقیم:

```powershell
python main.py hill-encrypt --text "HELP" --key-matrix "3,3;2,5" --padding none
python main.py hill-decrypt --text "HIAT" --key-matrix "3,3;2,5" --padding none
```

بازیابی کلید:

```powershell
python main.py hill-attack --plaintext "HELP" --ciphertext "HIAT" --block-size 2
```

## منابع پروژه

### داده‌ها

پوشه‌های `data` شامل موارد زیر هستند:

- متن‌های نمونهٔ انگلیسی
- متن نمونهٔ فارسی
- پیکره‌های مرجع برای تحلیل آماری
- فایل‌های ورودی مورد استفاده در آزمایش‌ها

این داده‌ها برای آزمایش رمزگذاری، تحلیل متن و بررسی دقت روش‌های رمز‌شکنی استفاده می‌شوند.

### خروجی‌ها

پوشه‌های `output` می‌توانند شامل موارد زیر باشند:

- متن رمزگذاری‌شده
- متن رمزگشایی‌شده
- متن بازیابی‌شده
- گزارش‌های آماری
- فایل‌های CSV و JSON
- نمودارهای PNG

### Benchmarkها

پوشه‌های `benchmarks` نتایج آزمایش‌های انجام‌شده روی متن‌هایی با طول متفاوت را نگه می‌دارند. از این نتایج برای مقایسهٔ دقت و زمان اجرای روش‌ها استفاده می‌شود.

### مستندات

پوشه‌های `docs` شامل توضیحات تکمیلی، تصاویر و گزارش‌های پروژه هستند. بخش رمز سزار دارای گزارش فارسی در قالب‌های Markdown، LaTeX و PDF است.

## اجرای تست‌ها

تست بخش سزار:

```powershell
cd Caesar-kntu
python -m pytest
```

تست بخش جانشینی:

```powershell
cd substitution
python -m unittest discover -s tests -v
```

تست بخش ویژنر:

```powershell
cd vigenere_project
python -m unittest discover -s tests -v
```

تست بخش هیل:

```powershell
cd hill_project
python -m unittest discover -s tests -v
```

## محدودیت‌ها

- این پروژه فقط برای اهداف آموزشی طراحی شده است.
- کیفیت رمز‌شکنی به طول متن و داده‌های مرجع وابسته است.
- تحلیل متن‌های کوتاه ممکن است نتیجهٔ دقیقی تولید نکند.
- زمان اجرای آزمایش‌ها به سخت‌افزار سیستم بستگی دارد.
- بیشتر بخش‌های پروژه روی حروف انگلیسی کار می‌کنند.
- بخش رمز جانشینی از زبان‌های انگلیسی و فارسی پشتیبانی می‌کند.

## کاربرد پروژه

این پروژه برای تمرین و بررسی موضوعات زیر قابل استفاده است:

- حساب پیمانه‌ای
- جایگشت‌ها
- ماتریس‌ها و جبر خطی
- تحلیل آماری متن
- الگوریتم‌های جست‌وجو
- مبانی رمزنگاری کلاسیک
