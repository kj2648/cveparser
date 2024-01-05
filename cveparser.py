import re
import sys
import json
import requests
import traceback
from os import path
from glob import glob
from bs4 import BeautifulSoup
# from pprint import pprint


def parse_git_kernel_src(url) -> str:
    if not url:
        return ""
    res = requests.get(url)
    soup = BeautifulSoup(res.text, "html.parser")
    src = soup.select_one("#cgit > div.content > table td.lines > pre > code")
    return src.text


def parse_git_kernel_commit(url):
    base_url = "https://git.kernel.org"
    def trim_path(filepath):
        filepath = filepath if filepath != "/dev/null" else ""
        if filepath.startswith("a/") or filepath.startswith("b/"):
            filepath = filepath[2:]
        return filepath

    res = requests.get(url)
    soup = BeautifulSoup(res.text, "html.parser")
    selects = soup.select("#cgit > div.content > table.diff div.head")
    if not selects or len(selects) > 1:
        return None
    
    diff = selects[0]
    old_file = re.search(r"--- (.+)\+\+\+", diff.text).group(1)
    new_file = re.search(r"\+\+\+ (.+)", diff.text).group(1)
    old_file = trim_path(old_file)
    new_file = trim_path(new_file)
    ahrefs = diff.find_all("a")
    if len(ahrefs) == 2:
        old_link = path.join(base_url, ahrefs[0].get("href")[1:])
        new_link = path.join(base_url, ahrefs[1].get("href")[1:])
    elif len(ahrefs) == 1:
        link = path.join(base_url, ahrefs[0].get("href")[1:])
        if old_file:
            old_link = link
            new_link = ""
        elif new_file:
            old_link = ""
            new_link = link
        else:
            raise Exception()
    else:
        raise Exception()

    ret = dict()
    ret["commit"] = soup.select_one(".commit-info tr:nth-child(3) > td > a:nth-child(1)").text
    ret["subject"] = soup.select_one("#cgit > div.content > div.commit-subject").text
    ret["message"] = soup.select_one("#cgit > div.content > div.commit-msg").text
    ret["old_file"] = old_file
    ret["new_file"] = new_file
    ret["old_contents"] = parse_git_kernel_src(old_link)
    ret["new_contents"] = parse_git_kernel_src(new_link)
    return ret


def create_top_25_cwe_cves_from_nvd_json(in_dir, out_jsonpath):
    TOP_25_CWES = {787, 79, 89, 416, 78, 20, 125, 22, 352, 434, 862, 476, 287, 190, 502, 77, 119, 798, 918, 306, 362, 269, 94, 863, 276}
    top_25_cwe_cves = []
    # top_25_cwe_cnts = {i: 0 for i in TOP_25_CWES}
    for i in glob(path.join(in_dir, "**/*.json")):
        with open(i) as f:
            data = json.load(f)
            assert(len(data["vulnerabilities"]) == 1)
            cve_dict = data["vulnerabilities"][0]["cve"]
            if cve_dict["vulnStatus"] == "Rejected":
                continue
            weaknesses = cve_dict["weaknesses"]
            cwes = {j["value"] for i in weaknesses for j in i["description"]}
            cwes = {int(re.search(r"CWE-(\d+)", i).group(1)) for i in cwes if re.search(r"CWE-\d", i)}
            if cwes & TOP_25_CWES:
                item = dict()
                item["cve"] = cve_dict["id"]
                item["cwe"] = [f"CWE-{i}" for i in cwes]
                item["ref"] = [i["url"] for i in cve_dict["references"]]
                top_25_cwe_cves.append(item)
            # for cwe in cwes.intersection(TOP_25_CWES):
            #     top_25_cwe_cnts[cwe] += 1
    # pprint(top_25_cwe_cves)
    with open(out_jsonpath, "w") as f:
        json.dump(top_25_cwe_cves, f, indent=2)


def create_git_kernel_commits_from_cve_json(cve_jsonpath, octopack_jsonpath):
    with open(cve_jsonpath) as f:
        cve_list = json.load(f)
    ret = []
    for cve in cve_list:
        git_kernel_urls = {url for url in cve["ref"] if "://git.kernel.org/" in url}
        for url in git_kernel_urls:
            try:
                print(url)
                commit = parse_git_kernel_commit(url)
                if commit:
                    ret.append(commit)
            except Exception as e:
                print(url, e)
                traceback.print_exception(e)
    with open(octopack_jsonpath, "w") as f:
        json.dump(ret, f, indent=2)


def create_git_kernel_commits_from_master(out_dir):
    base_url = "https://git.kernel.org"
    list_url = path.join(base_url, "pub/scm/linux/kernel/git/torvalds/linux.git/log/?ofs=")
    url_idx = 0
    while True:
        url = list_url + str(url_idx)
        print("!", url)
        res = requests.get(url)
        soup = BeautifulSoup(res.text, "html.parser")
        commits = soup.select("#cgit > div.content > table > tr")[1:]

        ret = []
        for commit in commits:
            try:
                tds = commit.find_all("td")
                commit_title = tds[1].text
                commit_url = path.join(base_url, tds[1].a.get("href")[1:])
                commit_file_cnt = int(tds[3].text)
                if commit_title.startswith("Merge tag"):
                    continue
                if commit_file_cnt != 1:
                    continue
                item = parse_git_kernel_commit(commit_url)
                if item:
                    ret.append(item)
            except Exception as e:
                print(commit_url, e)
                traceback.print_exception(e)
        
        out_jsonpath = path.join(out_dir, f"{str(url_idx)}.log")
        url_idx += 200
        with open(out_jsonpath, "w") as f:
            json.dump(ret, f, indent=2)


if __name__ == "__main__":
    runner = sys.argv[1]
    if runner == "gen_top25":
        input_dir = sys.argv[2]
        cve_jsonpath = sys.argv[3]
        create_top_25_cwe_cves_from_nvd_json(input_dir, cve_jsonpath)
    elif runner == "gen_from_top25":
        cve_jsonpath = path.realpath(sys.argv[2])
        octopack_jsonpath = path.realpath(sys.argv[3])
        if cve_jsonpath == octopack_jsonpath:
            print("No way")
            exit()
        create_git_kernel_commits_from_cve_json(cve_jsonpath, octopack_jsonpath)
    elif runner == "gen_from_master":
        out_dir = sys.argv[2]
        create_git_kernel_commits_from_master(out_dir)
    else:
        print("[Usage1] gen_top25 {input_dir} {cve_jsonpath}")
        print("[Usage2] gen_from_top25 {cve_jsonpath} {octopack_jsonpath}")
        print("[Usage3] gen_from_master {out_dir}")
