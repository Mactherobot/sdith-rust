import argparse as ap
import json
import os
import random
import re
import subprocess
import itertools
from termcolor import cprint
from tabulate import tabulate
import collections
import numpy as np


parser = ap.ArgumentParser(
    description="Benchmark sdith-rust. Run a combination of combination of feature flags",
)
parser.add_argument("--features", type=str, default="")
parser.add_argument("--stick-features", type=str, default="merkle_batching")
parser.add_argument("--categories", type=str, default="one,three,five")
parser.add_argument("--profiles", type=str, default="release")
parser.add_argument("--test", type=str, default="api")
parser.add_argument("--rest", nargs=ap.REMAINDER, default="")
parser.add_argument("--out", type=str)
parser.add_argument("--cycles", action="store_true")
parser.add_argument("--print-result", nargs="*")
parser.add_argument("--print-latex", action="store_true")
parser.add_argument("--filter", nargs="*")

parser.add_argument("--dudect", type=int, default=0)

args = parser.parse_args()


# Printing


def get_num(num_str):
    match num_str:
        case "one":
            return 1
        case "three":
            return 3
        case "five":
            return 5
        case _:
            return 0


def get_key(result):
    return (
        result["category"],
        result["profile"],
        ",".join(result["features"]) if len(result["features"]) else "base",
    )


def combine_results(results):
    # Simplify results by turning categor,profile,features into keys'
    results = [
        {get_key(value): value["results"] for key, value in res_list.items()}
        for res_list in results
    ]

    # Combine results
    combined = results[0]
    for res in results[1:]:
        for key, value in res.items():
            if key in combined:
                for test in combined[key].keys():
                    combined[key][test] += ", " + value[test]
            else:
                combined[key] = value

    return combined


if args.print_result:
    if args.print_result is None:
        print("Please specify a test to print results for")
        exit(1)
    files = args.print_result
    results = [json.load(open(f, "r")) for f in files]
    results = combine_results(results)

    # Filter if specified
    if args.filter:
        results = {
            (category, profile, features): v
            for (category, profile, features), v in results.items()
            if category not in args.filter
            and profile not in args.filter
            and not any(f in features.split(",") for f in args.filter)
        }

    results = collections.OrderedDict(
        sorted(results.items(), key=lambda x: (get_num(x[0][0]), x[0][2]))
    )

    # Header row
    table = [
        ["Category/Profile", "Features"]
        + [test for test in next(iter(results.values()))]
    ]

    for (category, profile, features), res in results.items():
        table.append(
            [
                f"{category}/{profile}",
                features,
            ]
            + [v for v in res.values()]
        )

    print(f"Results for {', '.join(files)}")
    print(
        tabulate(
            table,
            headers="firstrow",
            tablefmt="latex" if args.print_latex else "fancy_grid",
        )
    )
    exit(0)

# Dudect

if args.dudect:
    data = dict()

    for i in range(1, args.dudect + 1):
        print(f"\rRunning dudect {i}/{args.dudect}", end="")

        # Run cargo run --example dudect and get the results
        dudect_results = subprocess.run(
            ["cargo", "run", "--example", "dudect"],
            stdout=subprocess.PIPE,  # Capture standard output
            stderr=subprocess.PIPE,  # Capture standard error
            text=True,  # Decode output as text
            bufsize=1,  # Line buffering for real-time output
        )

        # Get results: They are of the form
        # "bench gf256_mul_lookup             seeded with 0x24af349fb0532db6
        # bench gf256_mul_lookup             ... : n == +0.001M, max t = -1.63677, max tau = -0.06075, (5/tau)^2 = 6774"
        # ...
        # get name,t and max t.

        # Split into groups of two lines
        dudect_results = list(
            filter(lambda x: "bench " in x, dudect_results.stdout.split("\n"))
        )
        for i in range(0, len(dudect_results), 2):
            # Get name
            name = r"bench (?P<name>\S+)"
            name = re.search(name, dudect_results[i]).group("name")

            # Get t
            t = r"t = (?P<t>\S+),"
            t = re.search(t, dudect_results[i + 1]).group("t")

            if name not in data:
                data[name] = []
            data[name].append(float(t))

    print("\rDone running dudect              ")

    results = dict()

    for name, values in data.items():
        results[name] = dict()
        results[name]["mean"] = np.mean(values)
        results[name]["std_dev"] = np.std(values)
        results[name]["max"] = max(values)

    json.dump(results, open("dudect.json", "w"))

    exit(0)

# Benching

features = args.features.split(",")
stick_features = args.stick_features.split(",")


def print_run(features, category, profile, test):
    return f'Bench {test} for category "{category.upper()}" with features {features} -- [{profile}]'


def grab_results(out, test):
    # Regex pattern to match test names and time results
    testnamepattern = f"(?P<test_name>{test}?\/\S+)"
    timeresultpattern = r"time:\s+(\[\S+\s\S+\s(?P<test_res>\S+\s\S+)\s\S+\s\S+\])"

    # Test for the test name pattern and time result pattern
    testname = re.search(testnamepattern, out)
    timeresult = re.search(timeresultpattern, out)

    # If both patterns match, return the test name and time result
    if testname and timeresult:
        return (testname.group("test_name"), timeresult.group("test_res"))
    elif testname:
        return (testname.group("test_name"), None)
    elif timeresult:
        return (None, timeresult.group("test_res"))
    else:
        return (None, None)


def save_results(runUiid, cmd, results, features, category, profile):
    # Get json file
    data = {}

    filename = args.out if args.out else f"bench_{runUiid}.json"

    # Check if file exists
    if os.path.exists(filename):
        with open(filename, "r") as f:
            data = json.load(f)

    # Add new entry
    data[cmd] = {
        "runUiid": runUiid,
        "features": features,
        "category": category,
        "profile": profile,
    }
    data[cmd]["results"] = {}
    for res in results:
        data[cmd]["results"][res[0]] = res[1]

    # Save json file
    with open(filename, "w") as f:
        json.dump(data, f)


def get_command(features, stick_features, category, profile, test):
    return f"cargo bench --no-default-features --features {','.join(stick_features)},{','.join(features)},category_{category}{',cycles_per_byte' if args.cycles else ''} --profile={profile} {test}"


def run_benchmark(features, stick_features, category, profile, test):
    features = [f if f != "none" else "" for f in features]
    command = get_command(features, stick_features, category, profile, test)
    process = subprocess.Popen(
        command.split(" "),
        stdout=subprocess.PIPE,  # Capture standard output
        stderr=subprocess.PIPE,  # Capture standard error
        text=True,  # Decode output as text
        bufsize=1,  # Line buffering for real-time output
    )

    # Capture output while also printing to the terminal
    captured_output = []
    testname = None
    timeresult = None
    for line in process.stderr:
        cprint(line, "dark_grey", end="")  # Print to terminal in real-time cprint
    for line in process.stdout:
        _testname, _timeresult = grab_results(line, test)
        if _testname:
            testname = _testname
        if _timeresult:
            timeresult = _timeresult

        if testname and timeresult:
            captured_output.append((testname, timeresult))
            testname, timeresult = None, None

    # Wait for the process to finish
    process.wait()

    return command, captured_output


def get_all_combinations(features):
    # Generate all combinations
    all_combinations = []
    for r in range(1, len(features) + 1):  # r is the combination length
        all_combinations.extend(itertools.combinations(features, r))

    # Convert the combinations to lists (optional, as they are tuples by default)
    all_combinations = [list(comb) for comb in all_combinations]
    return all_combinations + [""]


# Run all combinations of features for each category
all_feature_combinations = get_all_combinations(features)
all_outer_combinations = list(
    itertools.product(args.profiles.split(","), args.categories.split(","))
)

runUiid = random.randint(0, 10000)

for i, (profile, category) in enumerate(all_outer_combinations):
    for j, features in enumerate(all_feature_combinations):
        cprint(
            f"Running combination [{profile}, {category}] ({i+1}/{len(all_outer_combinations)}) with features {stick_features} {features} ({j+1}/{len(all_feature_combinations)})",
            "blue",
            attrs=["bold"],
        )
        cprint(
            f"CMD: {get_command(features, stick_features,category, profile, args.test)}",
            "blue",
            attrs=["bold"],
        )
        cmd, res = run_benchmark(features, stick_features, category, profile, args.test)
        cprint(f"OUT: {res}", "green", attrs=["bold"])
        save_results(runUiid, cmd, res, features, category, profile)
