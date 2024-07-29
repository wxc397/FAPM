# FAPM
FAPM: A Fake Amplification Phenomenon Monitor to Filter DRDoS Attacks with P4 Data Plane
Note: This project is based on a test and prototyping framework available at https://github.com/nsg-ethz/p4-utils. So in order to compile successfully, you need to use this framework.

# Repository Overview

Our artifact includes the following directories:

**BMv2/**:the P4 code of FAPM

**controller/**:the python code for controller and the determination of cluster centers

# Experiment
- Configure the BMv2 switch with different P4 code:
```
"switches": {
      "s1": { "p4_src":"basic_forward.p4"  },
      "s2": { "p4_src":"basic_forward.p4"  },
      "s3": { "cpu_port":true,"p4_src":"fapm.p4"}
    }
```
- Run the topology and controller:
```
sudo p4run
sudo python controller.py
```

