// browser dail function, return a promise which product a Session class to Read/Write
export function dial(addr) {
    // https://developer.mozilla.org/en-US/docs/Web/API/WebSocket/WebSocket
    let ws = new WebSocket(addr)
    ws.binaryType = "arraybuffer"

    let session = new Session(ws)

    return new Promise((open_resolve, open_reject) => {
        ws.onerror = (event) => {
            open_reject(event)
            // change read queue state
            session._reader.close()
        }
        ws.onclose = (event) => {
            open_reject(event)
            // change read queue state
            session._reader.close()
        }
        ws.onmessage = (event) => {
            // push to read queue
            session._reader.push(event.data)
        }
        ws.onopen = () => {
            // return a session class
            open_resolve(session)
        }
    })
}

// Rust bind type for browser websocket
export class Session {
    constructor(ws) {
        this._ws = ws
        this._reader = new ReadQueue()
    }

    // return a promise which means when browser's write ok or not
    write(data) {
        if (this._ws.readyState === 1) {
            this._ws.send(data)
            return new Promise((resolve, reject) => {
                if (this._ws.readyState !== 1) {
                    return reject("WebSocket is closed");
                } else {
                    return resolve()
                }
            })
        } else {
            return Promise.reject("WebSocket is closed");
        }
    }

    // return a promise to product a arraybuffer or null
    read() {
        return this._reader.next()
    }

    isClosed() {
        return this._ws.readyState !== 1
    }

    close() {
        this._ws.close()
    }
}

class ReadQueue {
    constructor() {
        this.queue = []
        // always false, expect ws closed
        this.closed = false
        // cache read resolve when queue is empty
        this.cache_resolve = null
    }

    push(buffer) {
        if (this.cache_resolve !== null) {
            this.cache_resolve(buffer)
            this.cache_resolve = null
        } else {
            this.queue.push(Promise.resolve(buffer))
        }
    }

    close() {
        this.closed = true
        this.queue.push(Promise.resolve(null))
    }

    // return Promise<null> means websocket is closed
    next() {
        if (this.queue.length !== 0) {
            return this.queue.shift();
        } else {
            if (this.closed) {
                return new Promise.resolve(null)
            } else {
                return new Promise((resolve, _reject) => {
                    this.cache_resolve = resolve
                })
            }
        }
    }
}
