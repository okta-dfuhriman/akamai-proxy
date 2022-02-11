import { auth, hset, expire } from '@upstash/redis';
import * as Sentry from '@sentry/browser';

Sentry.init({
    dsn: SENTRY_DSN,
    tracesSampleRate: 1.0,
});

auth(UPSTASH_ENDPOINT, UPSTASH_TOKEN);

const setHash = async (state, akamaiHeader) => {
    try {
        const { data, error } = await hset(state, 'data', akamaiHeader);

        if (error) {
            Sentry.captureException(error);
        } else {
            await expire(state, UPSTASH_EXPIRE);
        }

        return { data, error };
    } catch (error) {
        Sentry.captureException(error);
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
        Sentry.captureException(error);
        throw error;
    }
};

const parseHeader = async (_data) => {
    try {
        let result = {};
        _data &&
            _data.split(';').forEach((item) => {
                const parsedItem = item.split('=');

                const key = parsedItem[0];
                const value = parsedItem[1];

                if (value && value.includes('|')) {
                    let nestedValue = {};

                    value.split('|').forEach((item) => {
                        const _parsedItem = item.split(':');

                        nestedValue[_parsedItem[0]] = _parsedItem[1];
                    });
                    result[key] = nestedValue;
                } else {
                    result[key] = value;
                }
            });

        return result;
    } catch (error) {
        Sentry.captureException(error);
        throw error;
    }
};

const handleRiskEvent = async ({ ipAddress, akamaiHeader }) => {
    try {
        const url = `${ORIGIN}/api/v1/risk/events/ip`;

        if (ipAddress) {
            const { score } = (await parseHeader(akamaiHeader)) || 0;
            let riskLevel;

            if (score >= 80) {
                riskLevel = 'HIGH';
            } else if (score >= 30) {
                riskLevel = 'MEDIUM';
            } else {
                riskLevel = 'LOW';
            }

            const body = {
                timestamp: new Date(),
                subjects: [
                    {
                        ip: ipAddress,
                        riskLevel: riskLevel,
                    },
                ],
            };

            fetch(url, { method: 'POST', body: JSON.stringify(body) })
                .then((resp) => {
                    if (!resp.ok()) {
                        Sentry.captureEvent(resp);
                    }
                })
                .catch((error) => {
                    Sentry.captureException(error);
                });
        }
    } catch (error) {
        Sentry.captureException(error);
        throw error;
    }
};

const handler = async (req, res) => {
    try {
        const { headers, url, method } = req || {};
        const { origin, host } = Object.fromEntries(headers) || {};

        const ipAddress = headers.get('cf-connecting-ip');
        const akamaiHeader = headers.get('akamai-user-risk') || AKAMAI_HEADER;

        handleRiskEvent({ ipAddress, akamaiHeader });

        const regex = /(?=\.).*/;
        const _origin = origin || 'https://' + host || ORIGIN;
        const domain = _origin.match(regex)[0] || '';

        const params = new URL(url).searchParams;

        const state = params.get('state');

        let newHeaders = new Headers(headers);

        // const akamaiHeader = `uuid=964d54b7-0821-413a-a4d6-8131770ec8d5;requestid=135a5cdc;status=0;score=${SCORE};risk=unp:432/H|ugp:ie/M;trust=utp:weekday_1|udfp:be44fff67b66ec7b;general=aci:T;allow=0;action=none`;

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
        Sentry.captureException(error);
        throw error;
    }
};

addEventListener('fetch', (event) => {
    try {
        return event.respondWith(handler(event.request));
    } catch (error) {
        Sentry.captureException(error);
        return event.respondWith(
            new Response('Error thrown ' + error.message || error)
        );
    }
});
