FROM node:24-bookworm-slim AS build
WORKDIR /app
COPY package.json package-lock.json tsconfig.json tsconfig.build.json ./
COPY src ./src
# Third-party packages ship source maps; the image check (scripts/check-image.sh) allows none.
RUN npm ci && npm run build && npm ci --omit=dev && find node_modules -name "*.map" -type f -delete

FROM node:24-bookworm-slim AS runtime
WORKDIR /app
COPY --from=build /app/package.json ./package.json
COPY --from=build /app/node_modules ./node_modules
COPY --from=build /app/dist ./dist
USER node
ENTRYPOINT ["node", "dist/cli.js"]
CMD ["serve"]
