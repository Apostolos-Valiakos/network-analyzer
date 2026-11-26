# Mutation testing of backend modules with mutmut 3. mutmut needs Linux, so
# this runs inside the backend image, from the repository root:
#
#   docker run --rm -v "<repo>:/repo:ro" --entrypoint sh \
#     network-analyzer-backend:latest /repo/tests/mutation/mutmut_docker.sh
#
# The repository is mounted read-only: the code is copied to /w in a flat
# layout (server/* at the root), so mutmut's module names (packet_table, ...)
# match how the tests import them. Only the test files in TESTS are kept,
# because mutmut's first pass runs every test it finds.
#
# Prints killed/survived per module and the surviving mutants.

# Modules to mutate (server/<name>) and the tests that cover them; both can
# be overridden with docker run -e MUTATE=... -e TESTS=...
MUTATE="${MUTATE:-packet_table.py pcap_generator_service.py agglomerative_clustering.py}"
TESTS="${TESTS:-tests/backend/test_packet_table.py tests/backend/test_agglomerative.py tests/backend/test_pcap_service.py tests/backend/test_clustering.py tests/backend/test_ue_analysis.py tests/backend/test_role_evidence.py tests/backend/test_characterization.py}"
# Tests mutmut cannot follow (this one starts a real child process).
DESELECT="tests/backend/test_packet_table.py::test_real_child_process_runs_pipeline_without_database_setup"

set -e
mkdir -p /src /w
cd /repo
tar --exclude=node_modules --exclude=.git --exclude=.stryker-tmp --exclude='*.packets.tsv' \
    --exclude=server/generated_pcaps --exclude=server/uploads -cf - server tests pytest.ini | tar -xf - -C /src
cp -r /src/server/. /w/
cp -r /src/tests /w/tests
cp /src/pytest.ini /w/
cd /w

# The tests put ../../server on sys.path; in the flat layout that is ../..
grep -rl '"\.\.", "\.\.", "server"' tests | xargs sed -i 's/"\.\.", "\.\.", "server"/"..", ".."/'
for f in tests/backend/test_*.py; do
  case " $TESTS " in *" $f "*) ;; *) rm "$f" ;; esac
done

pip install -q -r tests/requirements.txt "mutmut>=3.4" 2>&1 | grep -v -i -E "notice|warning" || true
pip show mutmut | head -2
python -m pytest -q -p no:cacheprovider tests/backend 2>&1 | tail -1

exclude="tests|mutants|setup.cfg"
for m in $MUTATE; do exclude="$exclude|$m"; done
{
  echo "[mutmut]"
  echo "paths_to_mutate="; for m in $MUTATE; do echo "    $m"; done
  echo "tests_dir=tests/backend"
  echo "pytest_add_cli_args="; for d in $DESELECT; do echo "    --deselect"; echo "    $d"; done
  echo "pytest_add_cli_args_test_selection="; for t in $TESTS; do echo "    $t"; done
  # Everything else is copied as is; the mutated files must not be, or the
  # originals overwrite the mutants.
  echo "also_copy="; for p in $(ls -A | grep -v -E "^($exclude)\$"); do echo "    $p"; done; echo "    tests"
} > setup.cfg

timeout 3300 mutmut run --max-children 4 > /w/run.log 2>&1 || echo "mutmut exit $?"
tail -c 1500 /w/run.log | tr '\r' '\n' | tail -4

mutmut results --all true 2>/dev/null | awk -F': ' '{print $NF}' | sort | uniq -c
for m in $MUTATE; do
  name="${m%.py}"
  echo "=== $name"
  mutmut results --all true 2>/dev/null | grep "^ *$name\." | awk -F': ' '{print $NF}' | sort | uniq -c
done
echo "=== survivors"
for id in $(mutmut results 2>/dev/null | grep ": survived" | sed 's/^ *//; s/: .*//'); do
  echo "## $id"
  mutmut show "$id" 2>/dev/null | grep -E '^[-+][^-+]'
done
