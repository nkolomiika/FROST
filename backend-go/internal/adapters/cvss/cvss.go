// Package cvss — порт FIRST.org CVSS v4.0 (референс cvss/cvss4.py) на Go.
// Считает base score по вектору. Таблицы — в constants_gen.go (сгенерированы из
// того же Python-пакета, поэтому совпадают бит-в-бит).
package cvss

import (
	"errors"
	"math"
	"strconv"
	"strings"
)

const epsilon = 1e-6

// ErrMalformed — вектор некорректен (префикс/поля/значения/обязательные метрики).
var ErrMalformed = errors.New("malformed CVSS4 vector")

func finalRounding(x float64) float64 {
	return math.Floor((x+epsilon)*10+0.5) / 10
}

func validValue(metric, value string) bool {
	for _, v := range metricValidValues[metric] {
		if v == value {
			return true
		}
	}
	return false
}

func parseVector(vector string) (map[string]string, error) {
	if vector == "" {
		return nil, ErrMalformed
	}
	if strings.HasSuffix(vector, "/") {
		return nil, ErrMalformed
	}
	if !strings.HasPrefix(vector, "CVSS:4.0/") {
		return nil, ErrMalformed
	}
	metrics := map[string]string{}
	fields := strings.Split(vector, "/")[1:]
	for _, field := range fields {
		if field == "" {
			return nil, ErrMalformed
		}
		kv := strings.SplitN(field, ":", -1)
		if len(kv) != 2 {
			return nil, ErrMalformed
		}
		metric, value := kv[0], kv[1]
		if _, dup := metrics[metric]; dup {
			return nil, ErrMalformed
		}
		if _, known := metricValidValues[metric]; !known {
			return nil, ErrMalformed
		}
		if !validValue(metric, value) {
			return nil, ErrMalformed
		}
		metrics[metric] = value
	}
	// mandatory
	for _, m := range metricsMandatory {
		if _, ok := metrics[m]; !ok {
			return nil, ErrMalformed
		}
	}
	return metrics, nil
}

func addMissingOptional(metrics map[string]string) {
	for _, abbr := range []string{"MAV", "MAC", "MAT", "MPR", "MUI", "MVC", "MVI", "MVA", "MSC", "MSI", "MSA"} {
		if v, ok := metrics[abbr]; !ok || v == "X" {
			metrics[abbr] = metrics[abbr[1:]]
		}
	}
	for _, abbr := range []string{"S", "AU", "R", "V", "RE", "U", "CR", "IR", "AR", "E"} {
		if _, ok := metrics[abbr]; !ok {
			metrics[abbr] = "X"
		}
	}
}

func mValue(metrics map[string]string, metric string) string {
	selected := metrics[metric]
	switch {
	case metric == "E" && selected == "X":
		return "A"
	case metric == "CR" && selected == "X":
		return "H"
	case metric == "IR" && selected == "X":
		return "H"
	case metric == "AR" && selected == "X":
		return "H"
	}
	if mod, ok := metrics["M"+metric]; ok && mod != "X" {
		return mod
	}
	return selected
}

func macroVector(metrics map[string]string) string {
	m := func(k string) string { return mValue(metrics, k) }
	eq1 := "None"
	eq2 := "None"
	eq3 := "None"
	eq4 := "None"
	eq5 := "None"
	eq6 := "None"

	if m("AV") == "N" && m("PR") == "N" && m("UI") == "N" {
		eq1 = "0"
	} else if (m("AV") == "N" || m("PR") == "N" || m("UI") == "N") &&
		!(m("AV") == "N" && m("PR") == "N" && m("UI") == "N") && m("AV") != "P" {
		eq1 = "1"
	} else if m("AV") == "P" || !(m("AV") == "N" || m("PR") == "N" || m("UI") == "N") {
		eq1 = "2"
	}

	if m("AC") == "L" && m("AT") == "N" {
		eq2 = "0"
	} else {
		eq2 = "1"
	}

	if m("VC") == "H" && m("VI") == "H" {
		eq3 = "0"
	} else if !(m("VC") == "H" && m("VI") == "H") && (m("VC") == "H" || m("VI") == "H" || m("VA") == "H") {
		eq3 = "1"
	} else if !(m("VC") == "H" || m("VI") == "H" || m("VA") == "H") {
		eq3 = "2"
	}

	if m("MSI") == "S" || m("MSA") == "S" {
		eq4 = "0"
	} else if !(m("MSI") == "S" || m("MSA") == "S") && (m("SC") == "H" || m("SI") == "H" || m("SA") == "H") {
		eq4 = "1"
	} else if !(m("MSI") == "S" || m("MSA") == "S") && !(m("SC") == "H" || m("SI") == "H" || m("SA") == "H") {
		eq4 = "2"
	}

	switch m("E") {
	case "A":
		eq5 = "0"
	case "P":
		eq5 = "1"
	case "U":
		eq5 = "2"
	}

	if (m("CR") == "H" && m("VC") == "H") || (m("IR") == "H" && m("VI") == "H") || (m("AR") == "H" && m("VA") == "H") {
		eq6 = "0"
	} else {
		eq6 = "1"
	}
	return eq1 + eq2 + eq3 + eq4 + eq5 + eq6
}

func extractValueMetric(metric, s string) string {
	idx := strings.Index(s, metric+":")
	if idx < 0 {
		return ""
	}
	after := s[idx+len(metric)+1:]
	if slash := strings.Index(after, "/"); slash >= 0 {
		return after[:slash]
	}
	return after
}

func lookup(macro string) float64 {
	if v, ok := cvssLookupGlobal[macro]; ok {
		return v
	}
	return math.NaN()
}

// Score вычисляет base score CVSS 4.0 по нормализованному вектору (с префиксом CVSS:4.0/).
func Score(vector string) (float64, error) {
	metrics, err := parseVector(vector)
	if err != nil {
		return 0, err
	}
	addMissingOptional(metrics)
	return computeBaseScore(metrics), nil
}

func computeBaseScore(metrics map[string]string) float64 {
	m := func(k string) string { return mValue(metrics, k) }

	avL := map[string]float64{"N": 0.0, "A": 0.1, "L": 0.2, "P": 0.3}
	prL := map[string]float64{"N": 0.0, "L": 0.1, "H": 0.2}
	uiL := map[string]float64{"N": 0.0, "P": 0.1, "A": 0.2}
	acL := map[string]float64{"L": 0.0, "H": 0.1}
	atL := map[string]float64{"N": 0.0, "P": 0.1}
	vcL := map[string]float64{"H": 0.0, "L": 0.1, "N": 0.2}
	viL := vcL
	vaL := vcL
	scL := map[string]float64{"H": 0.1, "L": 0.2, "N": 0.3}
	siL := map[string]float64{"S": 0.0, "H": 0.1, "L": 0.2, "N": 0.3}
	saL := siL
	crL := map[string]float64{"H": 0.0, "M": 0.1, "L": 0.2}
	irL := crL
	arL := crL

	mv := macroVector(metrics)

	allN := true
	for _, k := range []string{"VC", "VI", "VA", "SC", "SI", "SA"} {
		if m(k) != "N" {
			allN = false
			break
		}
	}
	if allN {
		return 0.0
	}
	value := cvssLookupGlobal[mv]

	eq1v, _ := strconv.Atoi(mv[0:1])
	eq2v, _ := strconv.Atoi(mv[1:2])
	eq3v, _ := strconv.Atoi(mv[2:3])
	eq4v, _ := strconv.Atoi(mv[3:4])
	eq5v, _ := strconv.Atoi(mv[4:5])
	eq6v, _ := strconv.Atoi(mv[5:6])

	j := func(a, b, c, d, e, f int) string {
		return strconv.Itoa(a) + strconv.Itoa(b) + strconv.Itoa(c) + strconv.Itoa(d) + strconv.Itoa(e) + strconv.Itoa(f)
	}
	eq1Next := j(eq1v+1, eq2v, eq3v, eq4v, eq5v, eq6v)
	eq2Next := j(eq1v, eq2v+1, eq3v, eq4v, eq5v, eq6v)

	var eq3eq6Next, eq3eq6NextL, eq3eq6NextR string
	splitEq3eq6 := false
	switch {
	case eq3v == 1 && eq6v == 1:
		eq3eq6Next = j(eq1v, eq2v, eq3v+1, eq4v, eq5v, eq6v)
	case eq3v == 0 && eq6v == 1:
		eq3eq6Next = j(eq1v, eq2v, eq3v+1, eq4v, eq5v, eq6v)
	case eq3v == 1 && eq6v == 0:
		eq3eq6Next = j(eq1v, eq2v, eq3v, eq4v, eq5v, eq6v+1)
	case eq3v == 0 && eq6v == 0:
		splitEq3eq6 = true
		eq3eq6NextL = j(eq1v, eq2v, eq3v, eq4v, eq5v, eq6v+1)
		eq3eq6NextR = j(eq1v, eq2v, eq3v+1, eq4v, eq5v, eq6v)
	default:
		eq3eq6Next = j(eq1v, eq2v, eq3v+1, eq4v, eq5v, eq6v+1)
	}
	eq4Next := j(eq1v, eq2v, eq3v, eq4v+1, eq5v, eq6v)
	eq5Next := j(eq1v, eq2v, eq3v, eq4v, eq5v+1, eq6v)

	scoreEq1Next := lookup(eq1Next)
	scoreEq2Next := lookup(eq2Next)
	var scoreEq3eq6Next float64
	if splitEq3eq6 {
		l := lookup(eq3eq6NextL)
		r := lookup(eq3eq6NextR)
		scoreEq3eq6Next = math.Max(l, r)
	} else {
		scoreEq3eq6Next = lookup(eq3eq6Next)
	}
	scoreEq4Next := lookup(eq4Next)
	scoreEq5Next := lookup(eq5Next)

	// max composed vectors
	eq1Maxes := maxComposedEq1[mv[0:1]]
	eq2Maxes := maxComposedEq2[mv[1:2]]
	eq3eq6Maxes := maxComposedEq3[mv[2:3]][mv[5:6]]
	eq4Maxes := maxComposedEq4[mv[3:4]]
	eq5Maxes := maxComposedEq5[mv[4:5]]

	var maxVectors []string
	for _, a := range eq1Maxes {
		for _, b := range eq2Maxes {
			for _, c := range eq3eq6Maxes {
				for _, d := range eq4Maxes {
					for _, e := range eq5Maxes {
						maxVectors = append(maxVectors, a+b+c+d+e)
					}
				}
			}
		}
	}

	var sdAV, sdPR, sdUI, sdAC, sdAT, sdVC, sdVI, sdVA, sdSC, sdSI, sdSA, sdCR, sdIR, sdAR float64
	for _, mx := range maxVectors {
		sdAV = avL[m("AV")] - avL[extractValueMetric("AV", mx)]
		sdPR = prL[m("PR")] - prL[extractValueMetric("PR", mx)]
		sdUI = uiL[m("UI")] - uiL[extractValueMetric("UI", mx)]
		sdAC = acL[m("AC")] - acL[extractValueMetric("AC", mx)]
		sdAT = atL[m("AT")] - atL[extractValueMetric("AT", mx)]
		sdVC = vcL[m("VC")] - vcL[extractValueMetric("VC", mx)]
		sdVI = viL[m("VI")] - viL[extractValueMetric("VI", mx)]
		sdVA = vaL[m("VA")] - vaL[extractValueMetric("VA", mx)]
		sdSC = scL[m("SC")] - scL[extractValueMetric("SC", mx)]
		sdSI = siL[m("SI")] - siL[extractValueMetric("SI", mx)]
		sdSA = saL[m("SA")] - saL[extractValueMetric("SA", mx)]
		sdCR = crL[m("CR")] - crL[extractValueMetric("CR", mx)]
		sdIR = irL[m("IR")] - irL[extractValueMetric("IR", mx)]
		sdAR = arL[m("AR")] - arL[extractValueMetric("AR", mx)]
		neg := false
		for _, d := range []float64{sdAV, sdPR, sdUI, sdAC, sdAT, sdVC, sdVI, sdVA, sdSC, sdSI, sdSA, sdCR, sdIR, sdAR} {
			if d < 0 {
				neg = true
				break
			}
		}
		if neg {
			continue
		}
		break
	}

	curEq1 := sdAV + sdPR + sdUI
	curEq2 := sdAC + sdAT
	curEq3eq6 := sdVC + sdVI + sdVA + sdCR + sdIR + sdAR
	curEq4 := sdSC + sdSI + sdSA

	step := 0.1
	availEq1 := value - scoreEq1Next
	availEq2 := value - scoreEq2Next
	availEq3eq6 := value - scoreEq3eq6Next
	availEq4 := value - scoreEq4Next
	availEq5 := value - scoreEq5Next

	maxSevEq1 := float64(maxSeverityEq1[eq1v]) * step
	maxSevEq2 := float64(maxSeverityEq2[eq2v]) * step
	maxSevEq3eq6 := float64(maxSeverityEq3Eq6[eq3v][eq6v]) * step
	maxSevEq4 := float64(maxSeverityEq4[eq4v]) * step

	n := 0
	var nsEq1, nsEq2, nsEq3eq6, nsEq4, nsEq5 float64
	if !math.IsNaN(availEq1) && availEq1 >= 0 {
		n++
		nsEq1 = availEq1 * (curEq1 / maxSevEq1)
	}
	if !math.IsNaN(availEq2) && availEq2 >= 0 {
		n++
		nsEq2 = availEq2 * (curEq2 / maxSevEq2)
	}
	if !math.IsNaN(availEq3eq6) && availEq3eq6 >= 0 {
		n++
		nsEq3eq6 = availEq3eq6 * (curEq3eq6 / maxSevEq3eq6)
	}
	if !math.IsNaN(availEq4) && availEq4 >= 0 {
		n++
		nsEq4 = availEq4 * (curEq4 / maxSevEq4)
	}
	if !math.IsNaN(availEq5) && availEq5 >= 0 {
		n++
		nsEq5 = availEq5 * 0
	}

	meanDistance := 0.0
	if n != 0 {
		meanDistance = (nsEq1 + nsEq2 + nsEq3eq6 + nsEq4 + nsEq5) / float64(n)
	}
	value -= meanDistance
	value = math.Max(0.0, value)
	value = math.Min(10.0, value)
	return finalRounding(value)
}
