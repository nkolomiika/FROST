package http

import (
	"net/http"

	"github.com/nkolomiika/frost/internal/adapters/http/apiv1"
	"github.com/nkolomiika/frost/internal/app/recon"
)

// Scanner-раздел рекона: раскрытие поддоменов, скан портов, обратный резолв.
// Роуты монтируются в ReconHandler.Register (farm_handlers.go).

func (h *ReconHandler) startSubdomainScan(w http.ResponseWriter, r *http.Request) {
	var req apiv1.SubFarmRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, err)
		return
	}
	h.start(w, r, recon.KindSubs, derefRaw(req.Raw))
}

func (h *ReconHandler) getSubdomainJob(w http.ResponseWriter, r *http.Request) {
	h.get(w, r, recon.KindSubs)
}

func (h *ReconHandler) startPortScan(w http.ResponseWriter, r *http.Request) {
	var req apiv1.PortScanRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, err)
		return
	}
	h.start(w, r, recon.KindPorts, derefRaw(req.Raw))
}

func (h *ReconHandler) getPortScanJob(w http.ResponseWriter, r *http.Request) {
	h.get(w, r, recon.KindPorts)
}

func (h *ReconHandler) startReverseScan(w http.ResponseWriter, r *http.Request) {
	var req apiv1.ReverseFarmRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, err)
		return
	}
	h.start(w, r, recon.KindReverse, derefRaw(req.Raw))
}

func (h *ReconHandler) getReverseJob(w http.ResponseWriter, r *http.Request) {
	h.get(w, r, recon.KindReverse)
}
