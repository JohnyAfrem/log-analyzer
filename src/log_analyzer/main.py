import sys

from pathlib import Path



def main() -> None:
    if len(sys.argv) != 2:
        print("Usage: python src/log_analyzer/main.py <logfile>")
        raise SystemExit(2)

    p = Path(sys.argv[1])

    if not p.exists():
        print(f"Error: file not found: {p}")
        raise SystemExit(1)

    line_count = 0
    with p.open("r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line_count += 1
            if line_count <= 2:
                print("PREVIEW:", line.strip())


    print(f"Total lines: {line_count}")




if __name__ == "__main__":
    main()
