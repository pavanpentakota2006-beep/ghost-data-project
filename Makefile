.PHONY: inspect sample run test package
inspect:  ## show dataset shapes + schema warnings
	python3 code/inspect_dataset.py
sample:   ## run + score the sample set
	python3 code/main.py --sample && python3 code/evaluation/evaluate.py --pred sample_pred.csv --gold dataset/sample_output.csv
run:      ## generate output.csv
	python3 code/main.py
test:
	python3 -m unittest discover -s code/tests -v
package:  ## full pipeline: score, output.csv, reports, code.zip
	python3 code/run_all.py
