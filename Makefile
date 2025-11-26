ID := draft-fossati-seat-early-attestation

$(ID).xml $(ID).txt $(ID).html: $(ID).md ; kdrfc --html --idnits $<

clean: ; $(RM) $(ID).xml $(ID).v2v3.xml $(ID).txt $(ID).html
