# Network Scanner

تطبيق سطح مكتب لفحص الشبكة المحلية، مكتوب بـ Rust ويستخدم `egui/eframe 0.28`.
يدعم اكتشاف الأجهزة عبر ARP، وفحص منافذ TCP بالتوازي، وعرض النتائج مباشرة،
والبحث والفرز، والتعرّف على الشركة من عنوان MAC، والتصدير إلى CSV.

## المتطلبات المشتركة

- **Rust 1.85 أو أحدث وCargo**؛ يفضّل تثبيتهما عبر [rustup](https://rustup.rs/).
- نسخة كاملة من المشروع تشمل `Cargo.toml` و`Cargo.lock` و`src/` و`data/` و`scripts/`.
  ملف `data/vendors.tsv` مطلوب أثناء البناء لأنه يُضمَّن في الملف التنفيذي.
- اتصال بالإنترنت لتنزيل أدوات البناء واعتماديات Cargo أول مرة. التعرّف على الشركات أثناء الفحص يعمل دون إنترنت.
- جلسة سطح مكتب وتعريف رسومي يدعم OpenGL لتشغيل الواجهة.
- بطاقة Ethernet أو Wi-Fi فعالة بعنوان IPv4، وصلاحية التقاط الحزم على النظام.
- Python 3 **اختياري** لتحديث قاعدة الشركات؛ ليس مطلوبًا للبناء أو التشغيل المعتاد.

نفّذ الأوامر التالية من مجلد المشروع الذي يحتوي على `Cargo.toml`.
أبقِ `Cargo.lock` واستخدم `--locked` للاحتفاظ بإصدارات الاعتماديات المثبتة.
المسارات أدناه تفترض عدم تخصيص `CARGO_TARGET_DIR` أو هدف البناء الافتراضي.

**حالة التحقق:** اجتاز المشروع البناء والاختبارات على Linux باستخدام Rust 1.85.1.
تعليمات Windows وmacOS مستندة إلى توثيق الأدوات، لكن لم يُختبر التطبيق عليهما محليًا.

## Linux

### 1. المتطلبات والتثبيت

تحتاج إلى مترجم C/C++ وأداة `pkg-config` ومكتبات سطح المكتب، مع أدوات `libcap`
لإدارة صلاحية `CAP_NET_RAW`. يلزم تشغيل الواجهة داخل جلسة X11 أو Wayland.

على **Ubuntu / Debian**:

```bash
sudo apt update
sudo apt install build-essential pkg-config curl ca-certificates \
  libxcb-render0-dev libxcb-shape0-dev libxcb-xfixes0-dev \
  libxkbcommon-dev libssl-dev libwayland-dev libgl1-mesa-dev \
  libcap2-bin
```

على التوزيعات الأخرى ثبّت الحزم المكافئة لمكتبات XCB وxkbcommon وWayland وOpenGL،
وأدوات البناء و`pkg-config` و`setcap/getcap` من مدير حزم التوزيعة.
قائمة مكتبات Linux الأساسية موثّقة في [eframe 0.28.1](https://github.com/emilk/egui/blob/0.28.1/crates/eframe/README.md).

إذا لم يكن Rust مثبتًا، اتبع [دليل Rust الرسمي](https://doc.rust-lang.org/book/ch01-01-installation.html)، أو:

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source "$HOME/.cargo/env"
rustc --version
cargo --version
```

### 2. البناء

```bash
cargo build --release --locked
```

الناتج: `target/release/network-scanner`.
لا تستخدم `sudo` لتشغيل Cargo أو لبناء المشروع.

او للبناء و التشغيل 

```bash
 sudo cargo run --release --locked
```
### 3. صلاحيات الالتقاط والتشغيل

افحص صلاحية الالتقاط دون إرسال حزم:

```bash
./target/release/network-scanner --check-capture
```

إذا ظهر `Packet capture ready`، شغّل التطبيق مباشرة:

```bash
./target/release/network-scanner
```

إذا ظهر رفض للصلاحية، يمكن منح **الملف التنفيذي فقط** صلاحية `CAP_NET_RAW`:

```bash
sudo setcap cap_net_raw=ep ./target/release/network-scanner
getcap ./target/release/network-scanner
./target/release/network-scanner --check-capture
./target/release/network-scanner
```

هذه صلاحية مستمرة تسمح بالتقاط الحزم الخام وإرسالها، حتى إزالتها أو استبدال الملف.
أغلق أي نسخة مفتوحة من التطبيق وأعد تشغيلها بعد منح الصلاحية.
قد تحتاج إلى إعادة منحها بعد إعادة البناء. لإزالتها:

```bash
sudo setcap -r ./target/release/network-scanner
```

يوجد أيضًا مشغّل يجمع البناء والفحص والتشغيل:

```bash
bash scripts/run-linux.sh
```

يبني المشغّل في `target/` داخل المشروع، ثم يفحص الوصول. **عند رفض الصلاحية فقط**
يستدعي `sudo setcap` لمنح الصلاحية المستمرة المذكورة أعلاه، ثم يشغّل الواجهة
بحساب المستخدم العادي. قد يطلب `sudo` كلمة مرور حسابك في الطرفية.

### 4. مشاكل شائعة على Linux

| المشكلة | الإجراء |
| --- | --- |
| `setcap: command not found` | ثبّت `libcap2-bin` على Ubuntu/Debian أو حزمة libcap المكافئة. |
| `Operation not permitted` رغم منح الصلاحية | أعد تشغيل الملف نفسه وتحقق بـ `getcap`. قد تمنع الحاوية أو إعدادات `nosuid`/`no_new_privs` تفعيل صلاحيات الملف. |
| فشل فتح النافذة | شغّل التطبيق داخل جلسة سطح مكتب وتحقق من تعريف OpenGL وإعدادات X11/Wayland. |
| لا تظهر أجهزة الشبكة الفعلية داخل حاوية أو VM أو WSL | قد تكون البطاقة المعروضة افتراضية وعلى شبكة مختلفة؛ استخدم نظامًا وبطاقة متصلين مباشرة بالشبكة المطلوبة. |

## Windows

### 1. المتطلبات والتثبيت

التعليمات التالية تستهدف **Windows بمعمارية x64**:

1. ثبّت [Visual Studio Build Tools](https://visualstudio.microsoft.com/downloads/#build-tools-for-visual-studio-2022)
   مع حزمة **Desktop development with C++**، بما فيها مترجم MSVC وWindows SDK.
   راجع [إعداد Rust على Windows من Microsoft](https://learn.microsoft.com/en-us/windows/dev-environment/rust/setup).
2. ثبّت Rust عبر [rustup](https://rustup.rs/) واختر سلسلة أدوات **MSVC**.
   مكتبة `pnet` المستخدمة هنا تتطلب MSVC على Windows.
3. ثبّت [Npcap](https://npcap.com/#download)، مع تفعيل **WinPcap API-compatible Mode**.
   برنامج التشغيل Npcap مطلوب لتشغيل التطبيق، وليس للبناء فقط.
4. نزّل **Npcap SDK** من الموقع نفسه وفك ضغطه، مثلًا إلى `C:\npcap-sdk`.
   برنامج تثبيت Npcap وSDK عنصران منفصلان؛ البناء يحتاج `Packet.lib` من SDK.

متطلبات الربط موضّحة في [توثيق pnet](https://github.com/libpnet/libpnet#windows)،
وتفاصيل SDK والتوافق في [دليل تطوير Npcap](https://npcap.com/guide/npcap-devguide.html).

### 2. إعداد بيئة البناء

افتح **Developer PowerShell for Visual Studio** بإعداد x64، ثم انتقل إلى مجلد المشروع.
نفّذ التالي مع تعديل مسار SDK ليتطابق مع مكان فك الضغط:

```powershell
rustup toolchain install stable-x86_64-pc-windows-msvc
$env:LIB = "C:\npcap-sdk\Lib\x64;$env:LIB"
Test-Path "C:\npcap-sdk\Lib\x64\Packet.lib"
```

يجب أن يعيد `Test-Path` القيمة `True`. إعداد `LIB` هنا يخص جلسة PowerShell الحالية؛
أعده عند فتح جلسة بناء جديدة. يجب أن تتطابق معمارية `Packet.lib` مع معمارية Rust.

### 3. البناء والتشغيل

```powershell
cargo +stable-x86_64-pc-windows-msvc build --release --locked
.\target\release\network-scanner.exe --check-capture
.\target\release\network-scanner.exe
```

الناتج: `target\release\network-scanner.exe`.

إذا كانت إعدادات Npcap تقصر الالتقاط على المسؤولين وظهر رفض للوصول، افتح
PowerShell باستخدام **Run as administrator**، وانتقل إلى مجلد المشروع، ثم:

```powershell
.\target\release\network-scanner.exe --check-capture
.\target\release\network-scanner.exe
```

لا تحتاج إلى بناء المشروع بصلاحيات المسؤول.
قد تختلف متطلبات الرفع بحسب إعداد Npcap؛ راجع [دليل مستخدم Npcap](https://npcap.com/guide/npcap-users-guide.html).

### 4. مشاكل شائعة على Windows

| المشكلة | الإجراء |
| --- | --- |
| `link.exe not found` | ثبّت مكونات C++ وWindows SDK، واستخدم Developer PowerShell. |
| `cannot open file 'Packet.lib'` | تحقق من مسار `LIB` ووجود الملف في SDK وتطابق المعمارية. |
| `Packet.dll` مفقود أو فشل فتح بطاقة الالتقاط | تحقق من تثبيت Npcap ووضع التوافق مع WinPcap؛ وجود SDK وحده لا يكفي. |
| رفض الوصول | راجع وضع التقييد على المسؤولين في Npcap ثم أعد تشغيل التطبيق بالصلاحيات المناسبة. |
| تأخر انتهاء الفحص أو الإلغاء على شبكة هادئة | خلفية Windows في `pnet 0.35` لا تطبّق مهلة القراءة المعيّنة؛ قد تنتظر استقبال حزمة. إغلاق النافذة لا ينتظر عامل الالتقاط. |

## macOS

### 1. المتطلبات والتثبيت

- جهاز Mac بمعمارية Intel أو Apple Silicon، مع بناء محلي لسلسلة أدوات Rust الموافقة للجهاز.
- أدوات **Xcode Command Line Tools** لتوفير المترجم والرابط وSDK النظام.
- Rust وCargo، وصلاحية الوصول إلى أجهزة الالتقاط `/dev/bpf*`.

ثبّت أدوات Apple من Terminal:

```bash
xcode-select --install
```

انتظر اكتمال التثبيت ثم ثبّت Rust إن لم يكن موجودًا:

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source "$HOME/.cargo/env"
rustc --version
cargo --version
```

راجع [توثيق أدوات سطر الأوامر من Apple](https://developer.apple.com/library/archive/technotes/tn2339/_index.html).
لا يحتاج هذا التطبيق إلى Npcap على macOS؛ يستخدم `pnet` واجهة BPF في النظام.

### 2. البناء

من مجلد المشروع:

```bash
cargo build --release --locked
```

الناتج: `target/release/network-scanner`، بمعمارية سلسلة أدوات Rust المستخدمة.
ليس ملفًا شاملًا للمعماريتين ولا حزمة تطبيق `.app`؛ شغّله من Terminal.

### 3. صلاحيات الالتقاط والتشغيل

اختبر الوصول أولًا:

```bash
./target/release/network-scanner --check-capture
```

لتمكين الالتقاط بحساب المستخدم العادي، يمكن تثبيت حزمة **ChmodBPF** المتاحة ضمن
ملف تثبيت Wireshark الرسمي (`Install ChmodBPF.pkg`). هذه الحزمة تضبط الوصول
إلى أجهزة BPF وتتطلب صلاحية مسؤول عند التثبيت. اتبع
[تعليمات Wireshark على macOS](https://www.wireshark.org/docs/wsug_html_chunked/ChBuildInstallOSXInstall.html)،
ثم افتح جلسة مستخدم جديدة إذا تغيّرت عضوية المجموعات وأعد الفحص والتشغيل:

```bash
./target/release/network-scanner --check-capture
./target/release/network-scanner
```

كبديل للتشغيل بصلاحيات المستخدم العادي، يمكن تشغيل النسخة المبنية بصلاحيات root:

```bash
sudo ./target/release/network-scanner
```

هذا البديل يشغّل التطبيق كله بصلاحيات root، وقد يجعل ملفات CSV الناتجة مملوكة له.
لا تستخدم `sudo cargo build`، ولا تستخدم `setcap` على macOS؛ فهو خاص بلينكس.

### 4. مشاكل شائعة على macOS

| المشكلة | الإجراء |
| --- | --- |
| خطأ في `clang` أو SDK أو أدوات المطور | أكمل تثبيت Command Line Tools وتحقق من `xcode-select -p`. |
| رفض فتح `/dev/bpf*` | تحقق من تثبيت وإعداد ChmodBPF ومن صلاحيات الحساب، ثم أعد تشغيل التطبيق. |
| تشغيل ملف مبني لمعمارية مختلفة | أعد البناء محليًا بسلسلة أدوات Rust الموافقة لمعمارية جهازك. |
| لا تظهر أجهزة من شبكة أخرى | اختر البطاقة وCIDR المتصلين مباشرة بالشبكة؛ اكتشاف ARP لا يعبر الموجّه. |

## استخدام التطبيق

1. اختر بطاقة الشبكة أو اترك الاختيار التلقائي؛ يفضّل التطبيق الشبكة المطابقة الأكثر تحديدًا.
2. أدخل CIDR محليًا مثل `192.168.1.0/24`.
3. أدخل المنافذ مثل `22, 80, 443, 8000-8010`، أو استخدم Common/Web.
   اترك الحقل فارغًا أو اختر ARP only لاكتشاف الأجهزة فقط.
4. اضغط Start scan. تظهر الأجهزة والمنافذ المفتوحة تدريجيًا، ويمكن الإلغاء بزر Stop scan.
5. ابحث بعنوان IP أو MAC أو اسم الشركة أو المنفذ، وصفِّ النتائج ورتّبها حسب الحاجة.
   انقر بزر الفأرة الأيمن على صف لنسخ العنوان أو المنافذ.
6. حدّد مسار CSV واضغط Export all to CSV. يعمل التصدير في الخلفية، ويشمل جميع
   الأجهزة المكتشفة حتى المخفية بالبحث، ولا يستبدل ملفًا موجودًا.

المسارات النسبية للتصدير تُفسّر نسبة إلى مجلد تشغيل البرنامج.
الحدود هي 4096 عنوانًا و256 منفذًا مختلفًا. الإعداد الافتراضي 256 اتصالًا متزامنًا
ومهلة 700 مللي ثانية؛ يمكن ضبطهما إلى 16–512 اتصالًا و100–3000 مللي ثانية.
تُرسل طلبات ARP مرتين مع انتظار أخير قدره ثانيتان. يُدرج الجهاز المحلي إذا كان ضمن النطاق.
شريط التقدّم يقيس فحوص TCP، وقد يزداد إجماليها أثناء اكتشاف أجهزة إضافية.

## تشخيص الصلاحيات

تتحقق الواجهة من فتح قناة الالتقاط في الخلفية، دون إرسال حزم، وتعرض إحدى الحالات:

| الحالة | المعنى |
| --- | --- |
| `Packet capture ready` | أمكن فتح قناة الالتقاط على البطاقة المختارة. |
| `Packet capture access denied` | النظام رفض الصلاحية؛ اتبع خطوات نظامك أعلاه. |
| `Packet capture unavailable` | خطأ آخر، مثل عدم وجود بطاقة مطابقة أو مشكلة في برنامج التشغيل. |

على Linux ينسخ زر Copy permission fix أمرًا خاصًا **بالملف الجاري تشغيله**؛
منح صلاحية لنسخة `release` لا يمنحها لنسخة `debug`. أعد تشغيل التطبيق بعد تعديل الصلاحية.
زر Recheck capture access يعيد الفحص.

خيار `--check-capture` يفحص أول بطاقة IPv4 فعالة يجدها دون تشغيل الواجهة أو إرسال حزم.
قد تختلف عن البطاقة المختارة يدويًا داخل التطبيق. رموز الخروج:

| الرمز | المعنى |
| --- | --- |
| `0` | الالتقاط متاح. |
| `2` | الوصول مرفوض بسبب الصلاحيات. |
| `1` | خطأ آخر، بما فيه عدم العثور على بطاقة مناسبة. |

## قاعدة الشركات والقيود

قاعدة الشركات مضمّنة وتحتوي على أكثر من 58 ألف بادئة من سجلات IEEE العامة
MA-L وMA-M وMA-S وIAB، مع تفضيل المطابقة الأطول. الاسم يحدّد صاحب كتلة العناوين
وقد يكون مصنع بطاقة الشبكة، وليس العلامة التجارية للجهاز.
لا يرسل التطبيق عناوين MAC إلى خدمات خارجية.

- `Private MAC (vendor unavailable)`: العنوان محلي/عشوائي ولا يتيح تحديد الشركة بشكل موثوق.
- `Not in IEEE database`: لا توجد مطابقة في النسخة المضمّنة من السجل.
- اكتشاف ARP محصور في شبكة IPv4 المحلية ولا يعبر الموجّهات أو يشمل IPv6.
- الأجهزة التي لا تجيب عن ARP لا تُدرج؛ وقد يجعل Proxy ARP عدة عناوين تظهر تحت MAC واحد.
- فحوص TCP لا تميّز في النتائج بين رفض الاتصال وانتهاء المهلة.
- دعم مهلة قراءة الحزم يختلف باختلاف النظام وبرنامج التشغيل، وقد يؤخر الإلغاء أو انتهاء الفحص.

لتحديث قاعدة الشركات، يلزم Python 3 واتصال بالإنترنت، ثم إعادة البناء:

Linux / macOS:

```bash
python3 scripts/update-vendors.py
cargo build --release --locked
```

Windows، من جلسة البناء التي ضُبط فيها `LIB`:

```powershell
py -3 scripts/update-vendors.py
cargo +stable-x86_64-pc-windows-msvc build --release --locked
```

تفاصيل المصادر وتاريخ التنزيل محفوظة في [`data/README.md`](data/README.md) وملف البيانات.
على Linux أعد التحقق من صلاحية الملف التنفيذي بعد إعادة البناء.

## الاختبارات

تحتاج الاختبارات إلى متطلبات البناء الخاصة بنظامك. لا تحتاج إلى صلاحيات التقاط
ولا ترسل حزم فحص، واختبار الواجهة يعمل دون فتح نافذة.

Linux / macOS:

```bash
cargo test --locked
```

Windows، من جلسة Developer PowerShell المهيأة مع `LIB`:

```powershell
cargo +stable-x86_64-pc-windows-msvc test --locked
```

تغطي الاختبارات المدخلات ونطاقات المنافذ واختيار البطاقة وحزم ARP والتصفية وCSV،
وعرض 4096 نتيجة، وسلامة قاعدة الشركات وأولوية البادئات، وتصنيف أخطاء الصلاحيات.
