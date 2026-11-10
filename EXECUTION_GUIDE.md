# SafeFS – دليل التشغيل والاستخدام الأكاديمي الشامل
## Comprehensive Execution, Testing & Demonstration Guide

---

## 📖 جدول المحتويات / Table of Contents
1. [المتطلبات الأساسية / Prerequisites](#1-المتطلبات-الأساسية--prerequisites)
2. [التثبيت والتهيئة / Installation](#2-التثبيت-والتهيئة--installation)
3. [طريقة التشغيل / Running SafeFS](#3-طريقة-التشغيل--running-safefs)
4. [دليل استخدام الواجهات / Web Dashboard Pages Guide](#4-دليل-استخدام-الواجهات--web-dashboard-pages-guide)
5. [أداة العرض التفاعلي للأساتذة / Professor Demonstration Console](#5-أداة-العرض-التفاعلي-للأساتذة--professor-demonstration-console)
6. [تشغيل الاختبارات الآلية / Running Automated Tests](#6-تشغيل-الاختبارات-الآلية--running-automated-tests)
7. [الرفع على GitHub / Pushing to GitHub](#7-الرفع-على-github--pushing-to-github)

---

## 1. المتطلبات الأساسية / Prerequisites

- **نظام التشغيل:** Windows 10/11 أو Linux (Ubuntu, Debian, Fedora, Arch)
- **لغة بايثون:** Python 3.10 أو أحدث (تم الاختبار بنجاح على Python 3.13)
- **المتصفح:** Google Chrome, Microsoft Edge, Firefox, أو أي متصفح حديث

---

## 2. التثبيت والتهيئة / Installation

### على أنظمة Windows:
```powershell
# 1. الدخول إلى مجلد المشروع
cd C:\Users\awada\.gemini\antigravity\scratch\safefs

# 2. إنشاء بيئة عمل بايثون افتراضية (اختياري ولكن يُفضل)
python -m venv venv
.\venv\Scripts\activate

# 3. تثبيت المكتبات المطلوبة
pip install -r requirements.txt
```

### على أنظمة Linux:
```bash
# 1. الانتقال لمجلد المشروع
cd /path/to/safefs

# 2. إنشاء وتفعيل البيئة الافتراضية
python3 -m venv venv
source venv/bin/activate

# 3. تثبيت المكتبات
pip install -r requirements.txt
```

المكتبات الأساسية المستخدمة:
- `flask`: خادم الويب والواجهات الخلفية وواجهات REST API.
- `watchdog`: مراقبة نظام الملفات اللحظي عبر خطافات النواة (`ReadDirectoryChangesW` في ويندوز و `inotify` في لينكس).
- `psutil`: قراءة استهلاك الموارد المادية ومعلومات المعالج والذاكرة والتخزين ومعلومات نواة النظام.

---

## 3. طريقة التشغيل / Running SafeFS

لتشغيل النظام بالكامل مع تهيئة بيئة الاختبار التلقائية:

```bash
python run.py
```

ستظهر لك رسالة الإقلاع الترحيبية:
```text
===================================================================
  ____             __      _____ ____  
 / ___|  __ _ / _| ___|  ___/ ___| 
 \___ \ / _` | |_ / _ \ |_  \___ \ 
  ___) | (_| |  _|  __/  _|  ___) |
 |____/ \__,_|_|  \___|_|   |____/  
   SafeFS - Intelligent File System Monitoring & Recovery System
===================================================================

[*] Initializing SafeFS SQLite Database and Storage Engine...
[+] Initialized default monitored laboratory folder at: ...\demo_workspace
[*] Real-Time File System Observer: ACTIVE (Watchdog)
[*] Host Telemetry Engine: ACTIVE (Psutil)
[*] Rule-Based Threat Detection: ACTIVE (HIDS Heuristics)
[*] Web Server Running at: http://127.0.0.1:5000
[*] Press CTRL+C to terminate.
===================================================================
```

افتح المتصفح على العنوان التالي:
👉 **`http://127.0.0.1:5000`**

---

## 4. دليل استخدام الواجهات / Web Dashboard Pages Guide

يحتوي SafeFS على 10 صفحات احترافية متكاملة بتصميم داكن مستوحى من أنظمة الأمن السيبراني (DevSecOps):

1. **لوحة التحكم الرئيسية (Dashboard - `/`):**
   - تعرض 6 بطاقات إحصائية حية: الملفات المراقبة، المجلدات النشطة، الملفات المعدلة، الملفات المحذوفة، التهديدات المكتشفة، وإجمالي النسخ الاحتياطية.
   - رسوم بيانية تفاعلية عبر Chart.js لتوزيع العمليات ومصفوفة خطورة التهديدات.
   - جدول العمليات اللحظي الذي يتم تحديثه تلقائياً كل 4 ثوانٍ.

2. **مستكشف الملفات (File Explorer - `/explorer`):**
   - محاكاة لجدول الـ Inodes الخاص بنظام التشغيل.
   - يعرض المسارات، الأحجام، التجزئة المشفرة الحية SHA-256، وحالة الملف (`ACTIVE`, `MODIFIED`, `DELETED`, `MISSING`).
   - أزرار سريعة لكل ملف: زر التحقق من السلامة (`Verify`)، زر استعراض النسخ (`Versions`)، وزر معاينة المحتوى (`Preview`).
   - زر علوي لفحص سلامة جميع ملفات المجلد دفعة واحدة.

3. **المراقبة اللحظية (Live Monitoring - `/monitoring`):**
   - يعرض تدفق عمليات نظام الملفات الملتقطة من نواة النظام لحظة بلحظة.
   - إمكانية تصفية الأحداث بحسب النوع (`CREATED`, `MODIFIED`, `DELETED`, `MOVED`).
   - أزرار إيقاف مؤقت للتدفق (Pause Stream) والتحكم في محرك المراقبة (Pause Engine).

4. **سجل النسخ الاحتياطية (Version History - `/versions`):**
   - قائمة بجميع النسخ التاريخية المحفوظة في مساحة تخزين آمنة ومعزولة.
   - محرك مقارنة الفروقات (Unified Diff Viewer) لمقارنة أي نسخة سابقة مع النسخة الحية الحالية سطراً بسطر.
   - إمكانية تنزيل أي نسخة سابقة أو حذف النسخ غير المرغوبة.

5. **مركز التعافي من الكوارث (Recovery Center - `/recovery`):**
   - تطبيق قاعدة الأمان الصارمة: **Zero-Data-Loss Invariant** (لن يتم استبدال أي ملف أثناء الاسترجاع إلا بعد أخذ نسخة احتياطية تلقائية من حالته الحالية تحت نوع `PRE_RESTORE`).
   - معالج استرجاع سريع لاختيار الملف واختيار نقطة الاسترجاع والضغط على `Restore`.
   - سجل تدقيق غير قابل للتلاعب (Audit Trail) يوثق كل عمليات الاسترجاع وتجزئة كل نسخة.

6. **لوحة كشف التهديدات (Threat Detection - `/threats`):**
   - محرك HIDS لكشف سلوكيات البرمجيات الخبيثة وبرامج الفدية وفقاً لقواعد محددة:
     - تعديل سريع لعدة ملفات في ثوانٍ معدودة (Ransomware Burst).
     - حذف جماعي سريع للملفات (Mass Deletion).
     - تغيير الامتداد إلى امتداد فدية مشبوه مثل `.locked` أو `.crypto`.
     - الامتدادات المزدوجة الخادعة مثل `invoice.pdf.exe`.
   - إمكانية وضع علامة "تم الحل" (Resolve) أو تجاهل التنبيه (Dismiss).

7. **سجلات النشاط والتدقيق (Activity Logs - `/logs`):**
   - سجل كامل لكل عملية تمت في النظام مع إمكانية البحث النصي والفلترة حسب الخطورة ونوع الحدث وتقسيم الصفحات (Pagination).

8. **معلومات وموارد النظام (System Telemetry - `/system`):**
   - قياس استهلاك المعالج وتوزيعه على كل نواة (Per-Core Load Bar Chart).
   - استهلاك الذاكرة العشوائية RAM ومساحة القرص الصلب ومعدل القراءة والكتابة (I/O).
   - معلومات تفصيلية عن عملية SafeFS الجارية (PID, Memory RSS, Threads).
   - معلومات نواة نظام التشغيل ووقت التشغيل (Uptime).

9. **الإعدادات (Settings - `/settings`):**
   - إضافة وحذف المجلدات المراقبة وفحصها يدوياً.
   - تعديل عتبات الكشف (حجم النوافذ الزمنية بالثواني، عدد الملفات المطلوبة لإطلاق التنبيهات، والحد الأقصى للنسخ المحتفظ بها).

10. **المفاهيم الأكاديمية (OS Concepts - `/os-concepts`):**
    - مرجع أكاديمي تفاعلي يشرح بدقة كيف ترتبط ميزات SafeFS بنظريات أنظمة التشغيل (VFS, Inodes, Copy-on-Write, Asynchronous I/O, Mutex Synchronization, Cryptographic Integrity).

---

## 5. أداة العرض التفاعلي للأساتذة / Professor Demonstration Console

لتسهيل عرض ومناقشة المشروع أمام أساتذة المادة ولجنة التقييم، تم تضمين سكريبت محاكاة تفاعلي يقوم بتوليد سيناريوهات واقعية حية دون الحاجة لتعديل الملفات يدوياً:

افتح موجه أوامر إضافي ونفّذ:
```bash
python demo/generate_test_data.py
```

ستظهر لك القائمة التفاعلية التالية:
```text
============================================================
 SafeFS - Interactive Operating Systems Demo Console
============================================================
1. Simulate Benign File Modification (Auto-versioning test)
2. Simulate Accidental File Deletion (Recovery test)
3. Simulate Ransomware Rapid Modification Burst (HIDS alert)
4. Simulate Ransomware Extension (.locked) Mutation
5. Simulate Trojan Double Extension (invoice.pdf.exe)
6. Simulate Mass File Renaming Burst
7. Reset Demo Environment
8. Exit
============================================================
Select demonstration scenario (1-8):
```

### السيناريوهات المقترحة للعرض أمام الأساتذة:

1. **السيناريو الأول (أخذ النسخ اللحظية التلقائية):**
   - اختر `1` لتعديل ملف `operating_systems_thesis.docx`.
   - افتح صفحة المراقبة اللحظية `/monitoring` وسترى التقاط الحدث في نفس اللحظة.
   - افتح صفحة النسخ `/versions` وشاهد النسخة الجديدة مع إمكانية فتح زر `Diff` لمشاهدة السطور التي أُضيفت بدقة!

2. **السيناريو الثاني (كشف هجوم فدية وتشفير سريع - Ransomware Burst):**
   - اختر `3` لمحاكاة تعديل 8 ملفات في أقل من ثانية واحدة.
   - افتح لوحة التحكم أو صفحة التهديدات `/threats`، ستلاحظ ظهور تنبيه أحمر عالي الخطورة **CRITICAL** يشرح السلوك المشبوه ويكشف أسماء الملفات المتأثرة.

3. **السيناريو الثالث (كشف امتدادات الفدية الخبيثة):**
   - اختر `4` لإنشاء ملف ينتهي بامتداد `.locked`.
   - يقوم محرك HIDS بإطلاق إنذار فوري يشير لاكتشاف نمط تشفير برمجيات الفدية.

4. **السيناريو الرابع (الاسترجاع الآمن وحماية البيانات):**
   - ادخل على مركز التعافي `/recovery`، واختر أي ملف تم تعديله أو حذفه، واضغط على استرجاع.
   - لاحظ أن النظام قام تلقائياً بإنشاء نسخة أمان `PRE_RESTORE` قبل استبدال الملف لضمان عدم فقدان أي بيانات أثناء الاسترجاع.

---

## 6. تشغيل الاختبارات الآلية / Running Automated Tests

تم بناء حزمة اختبارات برمجية شاملة تضمن عمل جميع الوظائف داخل بيئات عزل مؤقتة (`tempfile.TemporaryDirectory`) لحماية ملفاتك الشخصية:

```bash
python tests/test_safefs.py
```

**النتيجة المتوقعة:**
```text
......
----------------------------------------------------------------------
Ran 6 tests in 0.504s

OK
```

---

## 7. الرفع على GitHub / Pushing to GitHub

تمت تهيئة المستودع محلياً وتجهيز ملف التجاهل `.gitignore`. لرفع المشروع على حسابك في GitHub، اتبع الخطوات التالية:

1. ادخل على حسابك في [GitHub](https://github.com/) وأنشئ مستودعاً جديداً (New Repository) بالاسم الذي تريده، مثلاً: `SafeFS-OS-Project`.
2. انسخ رابط المستودع الجديد (مثلاً: `https://github.com/awadalaroomi/SafeFS-OS-Project.git`).
3. افتح الطرفية (Terminal / PowerShell) في مجلد المشروع ونفّذ الأوامر التالية:

```bash
cd C:\Users\awada\.gemini\antigravity\scratch\safefs

# ربط المستودع البعيد (استبدل الرابط برابط مستودعك الجديد)
git remote add origin https://github.com/YOUR_USERNAME/SafeFS-OS-Project.git

# تسمية الفرع الرئيسي
git branch -M main

# رفع جميع الملفات
git push -u origin main
```
