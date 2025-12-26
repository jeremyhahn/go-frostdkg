#!/bin/bash
set -e

# libp2p DKG node entrypoint script
# Starts either coordinator or participant based on NODE_TYPE

LOG_LEVEL=${LOG_LEVEL:-info}

log() {
    echo "[$(date -u '+%Y-%m-%d %H:%M:%S UTC')] $*"
}

case "$NODE_TYPE" in
    coordinator)
        log "Starting libp2p coordinator..."
        log "  Session ID: ${SESSION_ID}"
        log "  Threshold: ${THRESHOLD}"
        log "  Participants: ${PARTICIPANTS}"
        log "  Listen: ${LISTEN_ADDR:-0.0.0.0:9000}"

        # Start coordinator and save PeerID to file
        frostdkg coordinator \
            --protocol libp2p \
            --threshold "${THRESHOLD}" \
            --participants "${PARTICIPANTS}" \
            --session-id "${SESSION_ID}" \
            --listen "${LISTEN_ADDR:-0.0.0.0:9000}" \
            --verbose &

        COORDINATOR_PID=$!

        # Wait for coordinator to start and write ready file
        sleep 3
        touch /tmp/coordinator_ready
        log "Coordinator ready, PID: $COORDINATOR_PID"

        # Wait for coordinator process
        wait $COORDINATOR_PID
        ;;

    participant)
        log "Starting libp2p participant..."
        log "  Participant ID: ${PARTICIPANT_ID}"
        log "  Coordinator: ${COORDINATOR_ADDR}"
        log "  Threshold: ${THRESHOLD}"

        # Wait a bit for coordinator to fully initialize
        sleep 2

        # Run participant
        frostdkg participant \
            --protocol libp2p \
            --coordinator "${COORDINATOR_ADDR}" \
            --id "${PARTICIPANT_ID}" \
            --threshold "${THRESHOLD}" \
            --output "/data/keyshare_${PARTICIPANT_ID}.json" \
            --verbose

        EXIT_CODE=$?

        if [ $EXIT_CODE -eq 0 ]; then
            log "Participant ${PARTICIPANT_ID} completed successfully"
            log "Key share saved to /data/keyshare_${PARTICIPANT_ID}.json"

            # Write success marker
            echo "success" > /data/status
        else
            log "Participant ${PARTICIPANT_ID} failed with exit code $EXIT_CODE"
            echo "failed" > /data/status
            exit $EXIT_CODE
        fi

        # Keep container running for result inspection
        tail -f /dev/null
        ;;

    *)
        log "ERROR: Unknown NODE_TYPE: $NODE_TYPE"
        log "Set NODE_TYPE to 'coordinator' or 'participant'"
        exit 1
        ;;
esac
