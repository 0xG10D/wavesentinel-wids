# Development Guide

## Scope

WaveSentinel is a defensive-only wireless intrusion detection dashboard. Keep changes focused on monitoring, logging, and visualization. Do not add offensive attack automation or packet injection features.

## Recommended Environment

- Linux host for live monitor-mode capture
- Python 3.10 or newer
- `iw`, `iwconfig`, and `airmon-ng`
- A monitor-mode capable USB Wi-Fi adapter

Windows is fine for editing the repository, but real packet capture should be tested on Linux.

## Local Setup

Create and activate a virtual environment:

```bash
python3 -m venv venv
source venv/bin/activate
```

Install runtime dependencies:

```bash
pip install -r requirements.txt
```

Install developer tooling:

```bash
pip install -r requirements-dev.txt
```

You can also install the project in editable mode:

```bash
pip install -e ".[dev]"
```

## Local Validation

Run syntax validation:

```bash
python3 -m py_compile main.py web/app.py src/*.py
```

Run linting:

```bash
ruff check main.py src web/app.py
```

Check formatting:

```bash
black --check main.py src web/app.py
```

## Running WaveSentinel

Example lab workflow:

```bash
sudo airmon-ng start wlx6c1ff7d85510 4
sudo ../venv/bin/python3 -u main.py --interface wlan0mon --channel 4 --reset-session
python3 web/app.py
```

## Contribution Rules

- Keep the project defensive-only
- Do not add deauth or attack automation
- Keep code readable and comment only where it helps comprehension
- Update documentation when detection logic or runtime behavior changes
- Test the dashboard and syntax before submitting changes

## Branching And Commits

- Use short, descriptive branches such as `feature/dashboard-filter-fix` or `fix/interface-validation`
- Keep commits focused on one logical change set
- Include the verification command you ran in the pull request or handoff summary
