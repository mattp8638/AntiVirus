# Console blank-page fix and render checks

## Cause

React error #31 means an object was supplied as a child where display content was expected. The reported device System page interpolated arbitrary profile fields directly into JSX, including values inside its key/value list. A stored empty object in a scalar field could therefore unmount the whole console. TypeScript's `any` and response type parameters did not validate that JSON at runtime.

The review found the same unchecked display pattern across console pages and detail views. A separate Windows collector issue unwrapped collections returned from a PowerShell function: one disk, printer, startup entry or similar item could become an object instead of a list. That could also break profile findings or collection rendering.

## Fix

- `displayValue` protects dynamic display expressions throughout the page and component sources, as well as shared cards, modal titles, errors, severity badges and tables. Strings, finite numbers and real React content keep their behaviour. Unexpected objects show **Unavailable**; their fields are never dumped into the page. Invalid records produce a visible table error.
- Collection hooks declared as arrays now use `useListData` to validate the response before page code calls array methods. This updates 80 collection call sites throughout pages and detail panels.
- `PageBoundary` contains unexpected render errors to the current view, preserves console navigation, offers retry and resets when the page or subpage URL changes. It supplements the data fixes.
- `profile_shapes.py` normalizes known system-profile fields both when collecting a new report and when reading previously stored profiles. Known singleton collections are repaired. Structured values in scalar fields become unavailable, and unknown flags remain unknown. Extension sections are retained. No database migration is needed.
- The Windows collector retains arrays for disks, volumes, startup entries, printers, monitors, shares and audit policy at zero, one and multiple items.
- Missing encryption information is labelled **not reported**, so unavailable data does not certify that encryption is enabled or disabled.

## Verification

The exact empty-object System-tab failure was reproduced before the fix and is now a regression test. `npm run test:pages` also tests shared display controls, table failures and page-boundary recovery.

The route sweep derives its page inventory from `App.tsx`, renders every registered route and walks tabs, device subpages and available record details. It covers Android Location, Microsoft 365 administration, session recording and all remote-viewer panes. At this change, it checks **225 distinct route/tab/detail views** in **57 route tests**, plus focused rendering and response-validation tests. API requests use a fresh in-memory backend with synthetic records. Microsoft transport, the remote desktop peer and terminal widget are deterministic fixtures; these checks do not perform live Microsoft writes or execute a remote shell.

The Windows PowerShell 5.1 test parses the actual collector and executes its real collection assignments with a deterministic section provider. It verifies zero, one and two records, including JSON round trips. Cloud tests cover old stored profiles, singleton repair, scalar validation and retention of extension data. CI runs these checks alongside the existing build and remote-input tests.

Run locally from the repository:

```sh
python -m pip install -r cloud/requirements-dev.txt
cd console
npm ci
npm run build
npm run test:pages
npm run test:shapes
npm run test:remote
```

`FENRIR_UI_PYTHON` can point to the Python interpreter containing the cloud test dependencies. The route tests start and stop their own test backend and use no production credentials or database.

## Deployment

Deploy the updated cloud/console image, then refresh the browser to load its new hashed assets. The API also handles existing stored profiles, so the System-page repair does not require deleting data or waiting for another inventory collection. Update Windows agents through the normal signed installer/update flow to include the collector fix. The previously merged Ctrl+Alt+Del fix remains present.

These are render and API-contract checks. They do not establish live Windows SAS delivery, map-provider availability or the success of third-party administrative operations.
