# VERDICT results importer for Ghidra.
# Run in Ghidra Script Manager: imports VERDICT JSON and annotates indirect calls.
# @category VERDICT
# @menupath Tools.VERDICT.Import Results

import json
import os

def run():
    # Ask for VERDICT JSON file
    from javax.swing import JFileChooser
    chooser = JFileChooser()
    chooser.setDialogTitle("Select VERDICT results JSON")
    if chooser.showOpenDialog(None) != JFileChooser.APPROVE_OPTION:
        print("VERDICT: cancelled")
        return
    path = chooser.getSelectedFile().getAbsolutePath()

    data = json.load(open(path))
    results = data.get('results', [])
    program = getCurrentProgram()
    listing = program.getListing()

    annotated = 0
    for r in results:
        if not r.get('confidence'):
            continue
        try:
            site_addr = int(r['site_addr'], 16)
        except:
            continue
        targets = r.get('targets', [])
        evidence = r.get('evidence', 'UNKNOWN')
        conf = r.get('confidence', 0)

        addr = toAddr(site_addr)
        instr = listing.getInstructionAt(addr)
        if not instr:
            continue

        # Add plate comment with VERDICT evidence
        comment = "VERDICT: {} -> {} ({} conf={})".format(
            r['site_addr'],
            ', '.join(targets),
            evidence, conf
        )
        instr.setComment(instr.PLATE_COMMENT, comment)

        # Add bookmarks for targets
        for t in targets:
            try:
                t_addr = toAddr(int(t, 16))
                createBookmark(t_addr, "VERDICT", "VERDICT target from {}".format(r['site_addr']))
            except:
                pass
        annotated += 1

    print("VERDICT: annotated {} indirect call sites".format(annotated))

run()
