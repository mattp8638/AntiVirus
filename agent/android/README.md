# Fenrir Android agent

Puts a phone under Fenrir management: location history, **lost mode**, **find-my-phone alarm**, **lock**,
**erase**, messages from IT, and battery, storage, network and security posture in the console.

## Build

The Android SDK is needed (Android Studio, or `sdkmanager "platforms;android-35" "build-tools;35.0.0"`).

```sh
cd agent/android
./gradlew testDebugUnitTest assembleRelease
# -> app/build/outputs/apk/release/app-release.apk
```

CI (`.github/workflows/android.yml`) builds and tests it on every change under `agent/android/` and uploads
`fenrir-android.apk` as a workflow artifact.

**Signing.** Phones only upgrade an app signed with the same key, so create one release key and keep it:

```sh
keytool -genkeypair -v -keystore fenrir-release.jks -alias fenrir -keyalg RSA -keysize 4096 -validity 10000
```

Locally, put `keystore.properties` (`storeFile=…`, `storePassword=…`, `keyAlias=fenrir`, `keyPassword=…`) in this
folder. In GitHub, add the secrets `FENRIR_ANDROID_KEYSTORE_B64` (`base64 -w0 fenrir-release.jks`),
`FENRIR_ANDROID_KEYSTORE_PASSWORD` and `FENRIR_ANDROID_KEY_ALIAS`. Never commit the keystore.

## Publish

Copy the APK to the server as `deploy/releases/fenrir-android.apk` (Docker installs; kept across rebuilds) or `cloud/downloads/fenrir-android.apk` (run from source). It is then served at
`https://<server>/downloads/fenrir-android.apk`, which the enrolment page links to.

## Enrol a phone

1. Console: **Deploy agents → Add a phone** → choose the customer → **Create phone enrolment code**.
2. Phone: scan the QR code with the camera. The page that opens has the app download and **Open in Fenrir**.
   (Or open the app, tap **Scan enrolment code**, or type the server and code.)
3. In the app, turn on each item in **What Fenrir needs**: location (then *Allow all the time*), notifications,
   device admin, no battery restrictions and, on Android 14+, the lost-mode screen.

Each code enrols one phone and expires after 24 hours.

## Work profile (personal phones) or device admin

**Deploy agents → Add a phone** offers two set-ups:

- **Personal phone: work profile.** Scanning the code asks Android to create a work profile with Fenrir as its owner
  (the user accepts Android's screens). Fenrir then runs inside the work profile (apps with a briefcase badge),
  enrols from there and enforces the phone policy: the screen lock on the whole phone, and restrictions, apps,
  permissions and VPN inside the work profile. The personal side stays private. *Erase* removes the work profile
  only. If the server cannot be reached while the profile is made, open the work Fenrir app and tap **Try again**.
- **Device admin only.** As before: lock, erase, locate, lost mode. Android no longer lets an app enforce passcode
  or restriction policy this way, so the policy is *checked*: what is not met is reported and the user is asked
  (once per policy change) to fix it.

## Phone policy

**Policies → Android phones**: screen lock strength, lock timeout, erasing work data after failed unlocks,
encryption, developer options, security patch age, minimum Android version, rooted phones; camera, screenshots,
installs from outside a store, copy and paste to personal apps, adding accounts and Bluetooth sharing (work profile);
required apps (a company APK from an https URL, checked against its SHA-256, installs silently in a work profile;
store apps are offered to the user), blocked apps (hidden in a work profile, otherwise the user is asked to remove
them), automatic permission grants; Wi-Fi networks (Android asks the user once) and an always-on VPN app.

Each heartbeat reports compliance. The device's **Security → Compliance** shows each requirement, met or not, and a
phone that does not meet its policy raises one alert that closes itself when it does.

## Remote support

**Connect** on a phone shares its screen in the console's remote viewer:

1. The phone shows *"<technician> wants to see your screen"*. Tapping it opens Android's own screen-sharing prompt;
   ignoring it declines after two minutes. Android requires the user to allow every session.
2. While shared, a *Sharing your screen* notification stays up with **Stop**.
3. The technician can tap, swipe, scroll, type and press Back, Home, Recents and Notifications if the user has
   turned on **Fenrir remote support** in Settings → Accessibility (the app's *Optional* step opens it). Without it
   the session is view-only.

The app also holds a live connection to the server, so a session (or any action) starts within seconds instead of
at the next check-in.

## What each action does

| Console action | On the phone |
|---|---|
| Locate now | A fresh GPS/network fix, shown on the Location tab within a minute |
| Play alarm | The alarm tone at full alarm volume, even on silent, for 60 s (Stop in the notification) |
| Lock | Locks the screen (device admin) |
| Message | A notification from IT |
| Lost mode | Locks, shows the message and number over the lock screen, reports location every 5 minutes |
| Erase | Factory reset (device admin). See the note below |

The phone checks in every minute (every 30 s in lost mode) and reports its location every 15 minutes. A
10-minute wake alarm keeps it going while the phone sleeps. Location fixes and events queue while offline.

If someone turns off Fenrir's device-admin rights, the console raises **Phone protection turned off**.

## App protection

The phone checks every installed app, and each new install or update as it happens (plus every app once a day):

- **Where it came from**: an app store (Google Play, Galaxy Store, Amazon, Huawei, Xiaomi, OPPO, vivo) or sideloaded
  (installed by a browser, file manager or adb).
- **What it can do**: control the screen through an accessibility service, read text messages (one-time codes), draw
  over other apps, act as device administrator, read every notification, install other apps, hide its icon.
- **Fingerprints**: the SHA-256 of its APK and of its signing certificate, which the cloud checks against threat
  intelligence. APKs are only read again when an app is updated.

Each finding adds to a risk score; the combinations banking trojans (sideloaded + screen control + texts or overlays)
and stalkerware (hidden + sideloaded + recording, tracking or call logs) use push an app to high risk. The phone
tells its user once about a high-risk app, with a **Remove** button that opens Android's uninstall screen.

In the console, the phone's **Security → App protection** lists the apps with Fenrir's verdict: malicious or suspicious
(threat intelligence on the APK, the signer, or the package written `android:com.example.app`), risky (high risk),
worth a look (medium), clean or trusted. Policy (**Phone app protection**) decides which verdicts raise an alert; the
alert closes itself when the app is removed or trusted. From an app: **Remove from phone** (silent on company-owned
phones, otherwise the user is asked), **Suspend** (company-owned phones only: the app cannot run until allowed again)
and **Trust**. Policy can also suspend malicious apps automatically on company-owned phones.

What it does not do: it does not scan files other than installed apps, and it does not filter web traffic on the
phone; that needs Android's VPN or Private DNS, which is a separate piece of work.

## Limits, and device-owner (managed) phones

Android gives a normal app with device-admin rights *lock* but restricts the rest:

- **Erase** works for device admins up to Android 13. On Android 14+ Android only lets a **device-owner** agent
  erase. The console raises **Phone erase failed** if the phone refuses.
- **The lost message on the lock screen itself** needs device owner. Otherwise Fenrir shows its own lost-mode
  screen over the lock screen.

Company phones can make Fenrir the device owner. This only works on a phone that has just been factory reset,
before any account is added:

```sh
adb shell dpm set-device-owner uk.co.fenrirsecurity.agent/.FenrirAdminReceiver
```

At scale, use Android zero-touch or QR provisioning with the same component name.

## iPhone

On iOS, locate, lock and erase are reserved for Apple MDM. That needs an Apple Push certificate from the
organisation's Apple account and is a separate piece of work. iPhones can already use the console itself:
Safari → Share → **Add to Home Screen**.
