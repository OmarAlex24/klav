/**
 * The site's logo, drawn once for every place it appears: the header and the
 * docs layout (Logo.astro). It is Klav's pixel key, the same drawing as
 * klav.dev (apps/web/public/index.html) shifted up one row. Keep it a
 * single-colour mark; each place fills it with its own text colour.
 */
export const logo = {
  /** The drawing's box; callers size it by height and keep the ratio. */
  width: 8,
  height: 5,
  paths: [
    "M1 0h2v1H1zM0 1h1v1H0zM3 1h1v1H3zM0 2h1v1H0zM3 2h5v1H3zM0 3h1v1H0zM3 3h1v1H3zM5 3h1v1H5zM7 3h1v1H7zM1 4h2v1H1z",
  ],
};
