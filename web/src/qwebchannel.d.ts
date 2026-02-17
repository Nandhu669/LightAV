export declare class QWebChannel {
    constructor(transport: any, initCallback: (channel: QWebChannel) => void);
    objects: any;
    send(data: any): void;
    exec(data: any, callback: any): void;
}
