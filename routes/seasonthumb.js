// ------------------------------------------------------------------------------
// seasonthumb.js
// Route to generate league season thumbnail images (landscape) with a gradient
// background and an optional season label.
//
// The season may be supplied as a path segment or a query param:
//   /:league/seasonthumb/:season   (e.g. /nhl/seasonthumb/2025-26)
//   /:league/seasonthumb?season=2025-26
//
// The season label (and any title/subtitle overrides) is text drawn onto the
// image, so it is gated behind ALLOW_EVENT_OVERLAYS like every other text
// overlay in the app. With the flag off, the route still renders the bare
// league logo. Thumb size is 1440W x 1080H by default.
// ------------------------------------------------------------------------------

const providerManager = require('../helpers/ProviderManager');
const { findLeague } = require('../leagues');
const { generateSeasonThumb } = require('../generators/genericImageGenerator');
const { sendCachedOrGenerate, handleImageRouteError } = require('../helpers/routeUtils');
const { isEventOverlaysEnabled } = require('../helpers/featureFlags');
const logger = require('../helpers/logger');

module.exports = {
    paths: [
        "/:league/seasonthumb",
        "/:league/seasonthumb.png",
        "/:league/seasonthumb/:season"
    ],
    method: "get",
    handler: async (req, res) => {
        const { league } = req.params;
        const { title, subtitle } = req.query;

        // Season arrives as a path segment or query param; tolerate a trailing
        // .png on the path form (e.g. /nhl/seasonthumb/2025-26.png).
        const season = (req.params.season || req.query.season || '')
            .replace(/\.png$/i, '')
            .trim();

        try {
            const leagueObj = await findLeague(league);
            if (!leagueObj) {
                logger.warn('Unsupported league requested', {
                    League: league,
                    URL: req.url,
                    IP: req.ip
                });
                return res.status(400).json({ error: `Unsupported league: ${league}` });
            }

            // Get both league logo URLs (light and dark variants for contrast checking)
            const leagueLogoUrl = await providerManager.getLeagueLogoUrl(leagueObj, false);
            const leagueLogoUrlAlt = await providerManager.getLeagueLogoUrl(leagueObj, true);

            if (!leagueLogoUrl) {
                return res.status(404).json({ error: 'League logo not found' });
            }

            // Text overlays (season label, title/subtitle) are opt-in.
            const overlaysOn = isEventOverlaysEnabled();

            // Generate the season thumbnail
            const thumbnailBuffer = await generateSeasonThumb(leagueLogoUrl, {
                width: 1440,
                height: 1080,
                leagueLogoUrlAlt: leagueLogoUrlAlt,
                season: overlaysOn ? (season || undefined) : undefined,
                title: overlaysOn ? title : undefined,
                subtitle: overlaysOn ? subtitle : undefined,
                league: leagueObj.shortName
            });

            // Send successful response
            sendCachedOrGenerate(req, res, thumbnailBuffer);
        } catch (error) {
            handleImageRouteError(error, req, res, 'Season thumbnail generation failed');
        }
    }
};
