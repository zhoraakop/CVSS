const maxComposed = require('./MaxComposed.js');
const cvssLookup_global  = require('./CVSSLookup.js');
const lookup = cvssLookup_global.cvssLookup_global;

function cvss_score(cvssSelected, lookup, maxSeverityData, macroVectorResult) {
    AV_levels = {"N": 0.0, "A": 0.1, "L": 0.2, "P": 0.3}
    PR_levels = {"N": 0.0, "L": 0.1, "H": 0.2}
    UI_levels = {"N": 0.0, "P": 0.1, "A": 0.2}

    AC_levels = {'L': 0.0, 'H': 0.1}
    AT_levels = {'N': 0.0, 'P': 0.1}

    VC_levels = {'H': 0.0, 'L': 0.1, 'N': 0.2}
    VI_levels = {'H': 0.0, 'L': 0.1, 'N': 0.2}
    VA_levels = {'H': 0.0, 'L': 0.1, 'N': 0.2}

    SC_levels = {'H': 0.1, 'L': 0.2, 'N': 0.3}
    SI_levels = {'S': 0.0, 'H': 0.1, 'L': 0.2, 'N': 0.3}
    SA_levels = {'S': 0.0, 'H': 0.1, 'L': 0.2, 'N': 0.3}

    CR_levels = {'H': 0.0, 'M': 0.1, 'L': 0.2}
    IR_levels = {'H': 0.0, 'M': 0.1, 'L': 0.2}
    AR_levels = {'H': 0.0, 'M': 0.1, 'L': 0.2}

    E_levels = {'U': 0.2, 'P': 0.1, 'A': 0}

    if (["VC", "VI", "VA", "SC", "SI", "SA"].every((metric) => m(cvssSelected, metric) == "N")) {
        return 0.0
    }

    value = cvssLookup_global.cvssLookup_global[macroVectorResult]

    eq1 = parseInt(macroVectorResult[0])
    eq2 = parseInt(macroVectorResult[1])
    eq3 = parseInt(macroVectorResult[2])
    eq4 = parseInt(macroVectorResult[3])
    eq5 = parseInt(macroVectorResult[4])
    eq6 = parseInt(macroVectorResult[5])
    eq1_next_lower_macro = ''.concat(eq1 + 1, eq2, eq3, eq4, eq5, eq6)
    eq2_next_lower_macro = "".concat(eq1, eq2 + 1, eq3, eq4, eq5, eq6)

    if (eq3 == 1 && eq6 == 1) {
        eq3eq6_next_lower_macro = "".concat(eq1, eq2, eq3 + 1, eq4, eq5, eq6)
    } else if (eq3 == 0 && eq6 == 1) {
        eq3eq6_next_lower_macro = "".concat(eq1, eq2, eq3 + 1, eq4, eq5, eq6)
    } else if (eq3 == 1 && eq6 == 0) {
        eq3eq6_next_lower_macro = "".concat(eq1, eq2, eq3, eq4, eq5, eq6 + 1)
    } else if (eq3 == 0 && eq6 == 0) {
        eq3eq6_next_lower_macro_left = "".concat(eq1, eq2, eq3, eq4, eq5, eq6 + 1)
        eq3eq6_next_lower_macro_right = "".concat(eq1, eq2, eq3 + 1, eq4, eq5, eq6)
    } else {
        eq3eq6_next_lower_macro = "".concat(eq1, eq2, eq3 + 1, eq4, eq5, eq6 + 1)
    }
    
    eq4_next_lower_macro = "".concat(eq1, eq2, eq3, eq4 + 1, eq5, eq6)
    eq5_next_lower_macro = "".concat(eq1, eq2, eq3, eq4, eq5 + 1, eq6)
    score_eq1_next_lower_macro = cvssLookup_global.cvssLookup_global[eq1_next_lower_macro]
    score_eq2_next_lower_macro = cvssLookup_global.cvssLookup_global[eq2_next_lower_macro]

    if (eq3 == 0 && eq6 == 0) {
        score_eq3eq6_next_lower_macro_left = cvssLookup_global.cvssLookup_global[eq3eq6_next_lower_macro_left]
        score_eq3eq6_next_lower_macro_right = cvssLookup_global.cvssLookup_global[eq3eq6_next_lower_macro_right]

        if (score_eq3eq6_next_lower_macro_left > score_eq3eq6_next_lower_macro_right) {
            score_eq3eq6_next_lower_macro = score_eq3eq6_next_lower_macro_left
        } else {

            score_eq3eq6_next_lower_macro = score_eq3eq6_next_lower_macro_right
        }
    } else {
        score_eq3eq6_next_lower_macro = cvssLookup_global.cvssLookup_global[eq3eq6_next_lower_macro]
    }

    score_eq4_next_lower_macro = cvssLookup_global.cvssLookup_global[eq4_next_lower_macro]
    score_eq5_next_lower_macro = cvssLookup_global.cvssLookup_global[eq5_next_lower_macro]

    eq1_maxes = getEQMaxes(macroVectorResult, 1)
    eq2_maxes = getEQMaxes(macroVectorResult, 2)
    eq3_eq6_maxes = getEQMaxes(macroVectorResult, 3)[macroVectorResult[5]]
    eq4_maxes = getEQMaxes(macroVectorResult, 4)
    eq5_maxes = getEQMaxes(macroVectorResult, 5)

    max_vectors = []
    for (eq1_max of eq1_maxes) {
        for (eq2_max of eq2_maxes) {
            for (eq3_eq6_max of eq3_eq6_maxes) {
                for (eq4_max of eq4_maxes) {
                    for (eq5max of eq5_maxes) {
                        max_vectors.push(eq1_max + eq2_max + eq3_eq6_max + eq4_max + eq5max)
                    }
                }
            }
        }
    }
    for (let i = 0; i < max_vectors.length; i++) {
        max_vector = max_vectors[i]
        severity_distance_AV = AV_levels[m(cvssSelected, "AV")] - AV_levels[extractValueMetric("AV", max_vector)]
        severity_distance_PR = PR_levels[m(cvssSelected, "PR")] - PR_levels[extractValueMetric("PR", max_vector)]
        severity_distance_UI = UI_levels[m(cvssSelected, "UI")] - UI_levels[extractValueMetric("UI", max_vector)]

        severity_distance_AC = AC_levels[m(cvssSelected, "AC")] - AC_levels[extractValueMetric("AC", max_vector)]
        severity_distance_AT = AT_levels[m(cvssSelected, "AT")] - AT_levels[extractValueMetric("AT", max_vector)]

        severity_distance_VC = VC_levels[m(cvssSelected, "VC")] - VC_levels[extractValueMetric("VC", max_vector)]
        severity_distance_VI = VI_levels[m(cvssSelected, "VI")] - VI_levels[extractValueMetric("VI", max_vector)]
        severity_distance_VA = VA_levels[m(cvssSelected, "VA")] - VA_levels[extractValueMetric("VA", max_vector)]

        severity_distance_SC = SC_levels[m(cvssSelected, "SC")] - SC_levels[extractValueMetric("SC", max_vector)]
        severity_distance_SI = SI_levels[m(cvssSelected, "SI")] - SI_levels[extractValueMetric("SI", max_vector)]
        severity_distance_SA = SA_levels[m(cvssSelected, "SA")] - SA_levels[extractValueMetric("SA", max_vector)]

        severity_distance_CR = CR_levels[m(cvssSelected, "CR")] - CR_levels[extractValueMetric("CR", max_vector)]
        severity_distance_IR = IR_levels[m(cvssSelected, "IR")] - IR_levels[extractValueMetric("IR", max_vector)]
        severity_distance_AR = AR_levels[m(cvssSelected, "AR")] - AR_levels[extractValueMetric("AR", max_vector)]

        if ([severity_distance_AV, severity_distance_PR, severity_distance_UI, severity_distance_AC, severity_distance_AT, severity_distance_VC, severity_distance_VI, severity_distance_VA, severity_distance_SC, severity_distance_SI, severity_distance_SA, severity_distance_CR, severity_distance_IR, severity_distance_AR].some((met) => met < 0)) {
            continue
        }
        break
    }

    current_severity_distance_eq1 = severity_distance_AV + severity_distance_PR + severity_distance_UI
    current_severity_distance_eq2 = severity_distance_AC + severity_distance_AT
    current_severity_distance_eq3eq6 = severity_distance_VC + severity_distance_VI + severity_distance_VA + severity_distance_CR + severity_distance_IR + severity_distance_AR
    current_severity_distance_eq4 = severity_distance_SC + severity_distance_SI + severity_distance_SA
    current_severity_distance_eq5 = 0

    step = 0.1

    available_distance_eq1 = value - score_eq1_next_lower_macro
    available_distance_eq2 = value - score_eq2_next_lower_macro
    available_distance_eq3eq6 = value - score_eq3eq6_next_lower_macro
    available_distance_eq4 = value - score_eq4_next_lower_macro
    available_distance_eq5 = value - score_eq5_next_lower_macro

    percent_to_next_eq1_severity = 0
    percent_to_next_eq2_severity = 0
    percent_to_next_eq3eq6_severity = 0
    percent_to_next_eq4_severity = 0
    percent_to_next_eq5_severity = 0

    n_existing_lower = 0

    normalized_severity_eq1 = 0
    normalized_severity_eq2 = 0
    normalized_severity_eq3eq6 = 0
    normalized_severity_eq4 = 0
    normalized_severity_eq5 = 0

    maxSeverity_eq1 = maxSeverityData["eq1"][eq1] * step
    maxSeverity_eq2 = maxSeverityData["eq2"][eq2] * step
    maxSeverity_eq3eq6 = maxSeverityData["eq3eq6"][eq3][eq6] * step
    maxSeverity_eq4 = maxSeverityData["eq4"][eq4] * step

    if (!isNaN(available_distance_eq1)) {
        n_existing_lower = n_existing_lower + 1
        percent_to_next_eq1_severity = (current_severity_distance_eq1) / maxSeverity_eq1
        normalized_severity_eq1 = available_distance_eq1 * percent_to_next_eq1_severity
    }

    if (!isNaN(available_distance_eq2)) {
        n_existing_lower = n_existing_lower + 1
        percent_to_next_eq2_severity = (current_severity_distance_eq2) / maxSeverity_eq2
        normalized_severity_eq2 = available_distance_eq2 * percent_to_next_eq2_severity
    }

    if (!isNaN(available_distance_eq3eq6)) {
        n_existing_lower = n_existing_lower + 1
        percent_to_next_eq3eq6_severity = (current_severity_distance_eq3eq6) / maxSeverity_eq3eq6
        normalized_severity_eq3eq6 = available_distance_eq3eq6 * percent_to_next_eq3eq6_severity
    }

    if (!isNaN(available_distance_eq4)) {
        n_existing_lower = n_existing_lower + 1
        percent_to_next_eq4_severity = (current_severity_distance_eq4) / maxSeverity_eq4
        normalized_severity_eq4 = available_distance_eq4 * percent_to_next_eq4_severity
    }

    if (!isNaN(available_distance_eq5)) {
        n_existing_lower = n_existing_lower + 1
        percent_to_next_eq5_severity = 0
        normalized_severity_eq5 = available_distance_eq5 * percent_to_next_eq5_severity
    }
    if (n_existing_lower == 0) {
        mean_distance = 0
    } else {
        mean_distance = (normalized_severity_eq1 + normalized_severity_eq2 + normalized_severity_eq3eq6 + normalized_severity_eq4 + normalized_severity_eq5) / n_existing_lower
    }

    value -= mean_distance;
    if (value < 0) {
        value = 0.0
    }
    if (value > 10) {
        value = 10.0
    }
    return Math.round(value * 10) / 10
}

function getEQMaxes(lookup, eq) {
	return maxComposed.maxComposed["eq" +eq][lookup[eq - 1]]
}

function extractValueMetric(metric, str) {
    extracted = str.slice(str.indexOf(metric) + metric.length + 1)
    if (extracted.indexOf('/') > 0) {
        metric_val = extracted.substring(0, extracted.indexOf('/'));
    }
    else {
        metric_val = extracted
    }
    return metric_val
}

function m(cvssSelected, metric) {
    selected = cvssSelected[metric]

    if (metric == "E" && selected == "X") {
        return "A"
    }
    if (metric == "CR" && selected == "X") {
        return "H";
    }
    if (metric == "IR" && selected == "X") {
        return "H"
    }
    if (metric == "AR" && selected == "X") {
        return "H"
    }

    if (Object.keys(cvssSelected).includes("M" + metric)) {
        modified_selected = cvssSelected["M" + metric]
        if (modified_selected != "X") {
            return modified_selected
        }
    }

    return selected
}

function macroVector(cvssSelected) {

    if (m(cvssSelected, "AV") == "N" && m(cvssSelected, "PR") == "N" && m(cvssSelected, "UI") == "N") {
        eq1 = "0"
    }
    else if ((m(cvssSelected, "AV") == "N" || m(cvssSelected, "PR") == "N" || m(cvssSelected, "UI") == "N")
        && !(m(cvssSelected, "AV") == "N" && m(cvssSelected, "PR") == "N" && m(cvssSelected, "UI") == "N")
        && !(m(cvssSelected, "AV") == "P")) {
        eq1 = "1"
    }
    else if (m(cvssSelected, "AV") == "P"
        || !(m(cvssSelected, "AV") == "N" || m(cvssSelected, "PR") == "N" || m(cvssSelected, "UI") == "N")) {
        eq1 = "2"
    }

    if (m(cvssSelected, "AC") == "L" && m(cvssSelected, "AT") == "N") {
        eq2 = "0"
    }
    else if (!(m(cvssSelected, "AC") == "L" && m(cvssSelected, "AT") == "N")) {
        eq2 = "1"
    }

    if (m(cvssSelected, "VC") == "H" && m(cvssSelected, "VI") == "H") {
        eq3 = 0
    }
    else if (!(m(cvssSelected, "VC") == "H" && m(cvssSelected, "VI") == "H")
        && (m(cvssSelected, "VC") == "H" || m(cvssSelected, "VI") == "H" || m(cvssSelected, "VA") == "H")) {
        eq3 = 1
    }
    else if (!(m(cvssSelected, "VC") == "H" || m(cvssSelected, "VI") == "H" || m(cvssSelected, "VA") == "H")) {
        eq3 = 2
    }

    if (m(cvssSelected, "MSI") == "S" || m(cvssSelected, "MSA") == "S") {
        eq4 = 0
    }
    else if (!(m(cvssSelected, "MSI") == "S" || m(cvssSelected, "MSA") == "S") &&
        (m(cvssSelected, "SC") == "H" || m(cvssSelected, "SI") == "H" || m(cvssSelected, "SA") == "H")) {
        eq4 = 1
    }
    else if (!(m(cvssSelected, "MSI") == "S" || m(cvssSelected, "MSA") == "S") &&
        !((m(cvssSelected, "SC") == "H" || m(cvssSelected, "SI") == "H" || m(cvssSelected, "SA") == "H"))) {
        eq4 = 2
    }

    if (m(cvssSelected, "E") == "A") {
        eq5 = 0
    }
    else if (m(cvssSelected, "E") == "P") {
        eq5 = 1
    }
    else if (m(cvssSelected, "E") == "U") {
        eq5 = 2
    }

    if ((m(cvssSelected, "CR") == "H" && m(cvssSelected, "VC") == "H")
        || (m(cvssSelected, "IR") == "H" && m(cvssSelected, "VI") == "H")
        || (m(cvssSelected, "AR") == "H" && m(cvssSelected, "VA") == "H")) {
        eq6 = 0
    }
    else if (!((m(cvssSelected, "CR") == "H" && m(cvssSelected, "VC") == "H")
        || (m(cvssSelected, "IR") == "H" && m(cvssSelected, "VI") == "H")
        || (m(cvssSelected, "AR") == "H" && m(cvssSelected, "VA") == "H"))) {
        eq6 = 1
    }

    return eq1 + eq2 + eq3 + eq4 + eq5 + eq6
}

module.exports = { cvss_score, macroVector };
