# P4-2_Bloom-Filter

## Requirements

- Python 3
- No external Python packages are required; both implementations use only the Python standard library.

Run the commands from this folder so the scripts can find:

- `malicious_urls.txt`
- `non_malicious_urls.txt`

```powershell
cd "C:\Users\Gnome\Desktop\dsa assignment\P4-2_Bloom-Filter\Question 6"
```

## Running the Claude Version

The Claude implementation is in `bloom_urls_claude.py`.

```powershell
python bloom_urls_claude.py
```

This version uses the default files `malicious_urls.txt` and `non_malicious_urls.txt` from the same directory. It does not take command-line arguments.

## Running the GPT Version

The GPT implementation is in `bloom_urls_gpt.py`.

To run it with the default files and default target false-positive rate:

```powershell
python bloom_urls_gpt.py
```

To run it with explicit input files and settings:

```powershell
python bloom_urls_gpt.py --malicious malicious_urls.txt --non-malicious non_malicious_urls.txt --fp-rate 0.01
```

Optional GPT arguments:

- `--malicious`: path to the malicious URL file
- `--non-malicious`: path to the non-malicious URL file
- `--fp-rate`: target Bloom filter false-positive rate, for example `0.01` for 1%
- `--progress-every`: print progress every N URLs; use `0` to disable progress output

For example, to disable progress output:

```powershell
python bloom_urls_gpt.py --progress-every 0
```
