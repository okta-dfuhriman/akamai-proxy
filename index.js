const handler = async (req, res) => {
    let newHeaders = new Headers(req.headers);

    const akamaiHeader =
        'uuid=964d54b7-0821-413a-a4d6-8131770ec8d5;requestid=135a5cdc;status=0;score=50;risk=unp:432/H|ugp:ie/M;trust=utp:weekday_1|udfp:be44fff67b66ec7b;general=aci:T;allow=0;action=none';

    newHeaders.append('Akamai-User-Risk', akamaiHeader);

    const modifiedRequest = new Request(req, {
        headers: newHeaders,
    });

    console.log('=== newHeaders ===');
    for (let h of newHeaders.entries()) {
        console.log(h[0] + ': ' + h[1]);
    }
    console.log('======');

    // Forward to Okta
    const response = await fetch(modifiedRequest);

    const modifiedResponse = new Response(null, response);

    modifiedResponse.headers.append('Akamai-User-Risk', akamaiHeader);

    console.log(' ');
    console.log('=== responseHeaders ===');
    for (let h of modifiedResponse.headers.entries()) {
        console.log(h[0] + ': ' + h[1]);
    }
    console.log('======');
    return modifiedResponse;
};

addEventListener('fetch', (e) => {
    e.respondWith(handler(e.request));
});
