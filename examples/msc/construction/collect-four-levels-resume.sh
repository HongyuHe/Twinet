set -eu
cd /users/hy/tdn-evidence-v2/Twinet
sudo bin/twinet msc --spec examples/msc/construction/shared-four-levels.json --state-dir /users/hy/tdn-evidence-v2/private/repaired-shared-four-levels check --json | sudo tee /users/hy/tdn-evidence-v2/exports/shared-four-levels-check.json
sudo python3 /users/hy/tdn-evidence-v2/collect_coherent_v2.py --spec /users/hy/tdn-evidence-v2/Twinet/examples/msc/construction/redundant-four-levels.json --output /users/hy/tdn-evidence-v2/exports/redundant-four-levels-coherent-20261017T2208Z --configuration-id redundant-four-levels --case-ids NET-009-C01,NET-020-C01,NET-020-C02 --confirm-loaded-config --platform-interface-names gre0,gretap0,erspan0 --deployer-sha256 20992185239e9e70a7dcc118045017b4ce4ba498b7c3a2ffdd6527b9db5e3a52
cd /users/hy/tdn-evidence-v2/Twinet
sudo bin/twinet msc --spec examples/msc/construction/redundant-four-levels.json --state-dir /users/hy/tdn-evidence-v2/private/repaired-redundant-four-levels check --json | sudo tee /users/hy/tdn-evidence-v2/exports/redundant-four-levels-check.json
