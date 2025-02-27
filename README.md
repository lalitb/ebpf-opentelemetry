```marmaid
flowchart LR
    subgraph s0["Scenario 1: OTel Rust <br> instrumented application"]
        A["User Code"]
        C["OTel Rust API/SDK"]
        subgraph D["OTel Rust GIG/warm Exporter"]
            E["GIG/warm Uploader"]
        end
    end

    subgraph s1["Scenario 2: OTel Collector (Go)"]
            G["Receiver(s) & <br> Processors<br>"]
            subgraph I["GIG/warm Exporter"]
                J["GIG/warm Uploader FFI <br>(Golang to Rust)"]
                K["GIG/warm Uploader"]
            end
    end

    subgraph s2["Scenario 3: OTel Collector (Rust)"]
            L["Receiver(s) & <br> Processors<br>"]
            subgraph M["GIG/warm Exporter"]
                O["GIG/warm Uploader"]
            end
    end

    subgraph s3["Scenario 4: MDSD / MA Service"]
        P["GIG/warm uploader FFI <br> (C to Rust)"]
        Q["GIG/warm Uploader"]
    end

    Z["GIG/warm"]

    A -- invokes --> C
    C -- LogRecord --> D
    D -- Bond Serialized CS data over HTTPS --> Z

    G -- OTLP data --> I
    I -- Bond Serialized CS data over HTTPS --> Z

    L -- OTLP data --> M
    M -- Bond Serialized CS data over HTTPS --> Z

    s3 -- Bond Serialized CS data over HTTPS --> Z


classDef Class_02 stroke-width:1px, stroke-dasharray: 2,2;
    D:::Class_02
    E:::Class_02
    J:::Class_02
    K:::Class_02
    I:::Class_02
    O:::Class_02
    P:::Class_02
    Q:::Class_02
```
