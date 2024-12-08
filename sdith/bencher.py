import argparse as ap
import json
import os
import random
import re
import subprocess
import itertools
from termcolor import colored, cprint


parser = ap.ArgumentParser(
    description="Benchmark sdith-rust. Run a combination of combination of feature flags",
)
parser.add_argument("--features", type=str)
parser.add_argument("--categories", type=str, default="one,three,five")
parser.add_argument("--profiles", type=str, default="release")
parser.add_argument("--test", type=str, default="api")
parser.add_argument("--rest", nargs=ap.REMAINDER, default="")

args = parser.parse_args()

features = args.features.split(",")


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

    filename = f"bench_{runUiid}.json"

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
    data[cmd]['results'] = {}
    for res in results:
        data[cmd]['results'][res[0]] = res[1]

    # Save json file
    with open(filename, "w") as f:
        json.dump(data, f)


def get_command(features, category, profile, test):
    return f"cargo bench --no-default-features --features {','.join(features)},category_{category} --profile={profile} {test}"


def run_benchmark(features, category, profile, test):
    features = [f if f != "none" else "" for f in features]
    command = get_command(features, category, profile, test)
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
            f"Running combination [{profile}, {category}] ({i+1}/{len(all_outer_combinations)}) with features {features} ({j+1}/{len(all_feature_combinations)})",
            "blue",
            attrs=["bold"],
        )
        cprint(
            f"CMD: {get_command(features, category, profile, args.test)}",
            "blue",
            attrs=["bold"],
        )
        cmd, res = run_benchmark(features, category, profile, args.test)
        cprint(f"OUT: {res}", "green", attrs=["bold"])
        save_results(runUiid,cmd, res, features, category, profile)
        
