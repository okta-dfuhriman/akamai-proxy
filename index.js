import { auth, hset, expire } from '@upstash/redis';
import { checkIfFuntionParamPresent } from 'serverless-cloudflare-workers/shared/validate';

auth(UPSTASH_ENDPOINT, UPSTASH_TOKEN);

const setHash = async (state, akamaiHeader) => {
    try {
        const { data, error } = await hset(state, 'data', akamaiHeader);

        if (error) {
            console.log(error);
        } else {
            await expire(state, UPSTASH_EXPIRE);
        }

        return { data, error };
    } catch (error) {
        console.error(
            typeof error === 'string'
                ? new Error(`Unable to set hash [${error}]`)
                : error
        );
        throw error;
    }
};

/*
Function to set the common and necessary headers in order to handle CORS.
*/
const setCommonHeaders = async (resp, origin) => {
    try {
        /*
        In order for Set-Cookie to work, the 'Access-Control-Allow-Credentials' must be set.
        */
        resp.headers.set('Access-Control-Allow-Credentials', true);
        resp.headers.append(
            'Access-Control-Allow-Headers',
            'Set-Cookie, Content-Type'
        );
        resp.headers.set('Access-Control-Allow-Origin', origin || ORIGIN);
        resp.headers.set('Access-Control-Allow-Methods', 'GET, OPTIONS, POST');
        /*
           CORS requires a max age in order to set credentials.
           */
        resp.headers.set('Access-Control-Max-Age', 3600);
    } catch (error) {
        console.error(
            typeof error === 'string'
                ? new Error(`Unable to set common headers [${error}]`)
                : error
        );
        throw error;
    }
};

const handler = async (req, res) => {
    try {
        const { headers, url, method } = req || {};
        const { origin, host } = Object.fromEntries(headers) || {};

        const regex = /(?=\.).*/;
        const _origin = origin || 'https://' + host || ORIGIN;
        const domain = _origin.match(regex)[0] || '';

        const params = new URL(url).searchParams;

        const state = params.get('state');

        let newHeaders = new Headers(headers);

        const akamaiHeader = `uuid=964d54b7-0821-413a-a4d6-8131770ec8d5;requestid=135a5cdc;status=0;score=${SCORE};risk=unp:432/H|ugp:ie/M;trust=utp:weekday_1|udfp:be44fff67b66ec7b;general=aci:T;allow=0;action=none`;

        newHeaders.append('Akamai-User-Risk', akamaiHeader);

        const modifiedRequest = new Request(req, {
            headers: newHeaders,
        });

        // Cache the Akamai header
        await setHash(state, akamaiHeader);

        // Forward to Okta
        const response = await fetch(modifiedRequest, {
            withCredentials: true,
        });

        const modifiedResponse = new Response(await response.text(), response);

        if (method && method !== 'OPTIONS') {
            modifiedResponse.headers.append(
                'Set-Cookie',
                `aur=${Buffer.from(akamaiHeader).toString(
                    'base64'
                )}; Secure; HttpOnly; Path=/; Domain=${domain}; SameSite=None`
            );

            modifiedResponse.headers.append('Akamai-User-Risk', akamaiHeader);
        }

        await setCommonHeaders(modifiedResponse, origin);

        return modifiedResponse;
    } catch (error) {
        console.error(
            typeof error === 'string'
                ? new Error(`Encountered problem handling request [${error}]`)
                : error
        );
        throw error;
    }
};

addEventListener('fetch', (event) => {
    try {
        return event.respondWith(handler(event.request));
    } catch (error) {
        return event.respondWith(
            new Response('Error thrown ' + error.message || error)
        );
    }
});
